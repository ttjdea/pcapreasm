# SPDX-License-Identifier: MPL-2.0
"""pcapreasm 0.1.0 で追加・修正した挙動のテスト(安全性・入出力・統計・メモリ制御)。

実データは使わず、テスト内でバイト列から PCAP を合成します。
実行方法(リポジトリのルートで):
    python -m unittest discover -s tests -v
"""

import io
import logging
import os
import pathlib
import random
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import pcapreasm as P  # noqa: E402
from test_pcapreasm import (  # noqa: E402
    ACK, C, FIN, PSH, REQ, S, SYN, PcapTestCase, Recorder,
    http_like_session, ip4, ip6, make_pcap, ms, tcp, tcp_pkt, udp, udp_pkt,
)

# 性能系テストの上限秒数。0.0.1 の実装ではこの条件で 10 秒以上かかる。
# 遅い CI でも誤検知しないよう、通常の実行時間(1 秒未満)に対して大きめに取っている。
SLOW_LIMIT_SECONDS = 8.0


# ---------------------------------------------------------------------------
# 区間管理(増分の被覆判定の土台)
# ---------------------------------------------------------------------------
class TestIntervals(unittest.TestCase):
    @staticmethod
    def _runs(covered):
        runs = []
        for value in sorted(covered):
            if runs and runs[-1][1] == value:
                runs[-1][1] = value + 1
            else:
                runs.append([value, value + 1])
        return [tuple(run) for run in runs]

    def test_matches_naive_model(self):
        rnd = random.Random(1)
        for _ in range(300):
            intervals, covered = P._Intervals(), set()
            for _ in range(rnd.randrange(1, 30)):
                start = rnd.randrange(0, 60)
                end = start + rnd.randrange(0, 15)
                expect_new = not set(range(start, end)) <= covered
                self.assertEqual(intervals.add(start, end), expect_new)
                covered |= set(range(start, end))
            self.assertEqual(list(zip(intervals.starts, intervals.ends)), self._runs(covered))
            for base in range(0, 80):
                expected = base
                for run_start, run_end in self._runs(covered):
                    if run_start <= base < run_end:
                        expected = run_end
                self.assertEqual(intervals.reach(base), expected)


def _old_covers_up_to_fin(reassembler):
    """0.0.1 の実装(毎回ソートする版)。新実装の結果を照合するための基準。"""
    spans = sorted((seq, seq + len(payload)) for seq, payload, _ in reassembler.chunks)
    if reassembler.start_seq is not None:
        covered = reassembler.start_seq
    elif spans:
        covered = spans[0][0]
    else:
        covered = reassembler.fin_seq
    for start, end in spans:
        if start > covered:
            return False
        if end > covered:
            covered = end
    return covered >= reassembler.fin_seq


class TestFinCoverageEquivalence(unittest.TestCase):
    def test_incremental_result_equals_full_sort_result(self):
        rnd = random.Random(7)
        for trial in range(400):
            length = rnd.randrange(1, 200)
            isn = rnd.choice([1000, 0xFFFFFFF0, rnd.getrandbits(32)])
            with_syn = rnd.random() < 0.7
            segments, pos = [], 0
            while pos < length:
                size = rnd.randrange(1, 30)
                segments.append((pos, min(size, length - pos)))
                pos += size
            rnd.shuffle(segments)
            reassembler = P._TCPReassembler()
            data_start = isn + 1 if with_syn else isn
            if with_syn:
                reassembler.add(isn & 0xFFFFFFFF, b"", 0, P.TCP_SYN)
            fin_at = rnd.randrange(0, len(segments) + 1)  # この個数のセグメントが届いた後に FIN が届く
            for index in range(len(segments) + 1):
                if index == fin_at:
                    reassembler.add((data_start + length) & 0xFFFFFFFF, b"", 1, P.TCP_FIN | P.TCP_ACK)
                    self.assertEqual(reassembler.is_finished(), _old_covers_up_to_fin(reassembler), trial)
                if index == len(segments):
                    break
                offset, size = segments[index]
                if rnd.random() < 0.15:
                    continue  # この区間は届かない(欠損)
                reassembler.add((data_start + offset) & 0xFFFFFFFF, b"x" * size, 1, P.TCP_ACK)
                if index >= fin_at:
                    self.assertEqual(reassembler.is_finished(), _old_covers_up_to_fin(reassembler), trial)


# ---------------------------------------------------------------------------
# CPU の二次計算量(0.0.1 では数秒〜数十秒かかった入力)
# ---------------------------------------------------------------------------
class TestNoQuadraticBlowup(PcapTestCase):
    def test_many_tiny_ip_fragments(self):
        count = 20000
        pkts = [(ms(0), ip4(C, S, 17, b"Z", ident=7, frag_field=1))]  # 最終フラグメント(オフセット 8)
        for i in range(count):
            pkts.append((ms(1), ip4(C, S, 17, b"A", ident=7, frag_field=0x2000 | (2 * (i % 4000)))))
        started = time.monotonic()
        _, proc = self.run_pcap(make_pcap(pkts))
        self.assertLess(time.monotonic() - started, SLOW_LIMIT_SECONDS)
        self.assertEqual(proc.stats["fragments"], count + 1)

    def test_many_small_segments_after_fin_with_unfilled_gap(self):
        count = 20000
        pkts = [
            tcp_pkt(0, C, 1234, S, 80, 1000, 0, SYN),
            tcp_pkt(1, C, 1234, S, 80, 1_000_000, 0, FIN | ACK),  # FIN は遠く、間は埋まらない
        ]
        for i in range(count):
            pkts.append(tcp_pkt(2, C, 1234, S, 80, 1001 + 2 * i, 0, ACK, b"A"))
        started = time.monotonic()
        rec, _ = self.run_pcap(make_pcap(pkts))
        self.assertLess(time.monotonic() - started, SLOW_LIMIT_SECONDS)
        self.assertEqual(rec.streams[0][2].segment_count, count)


class TestFragmentReassemblyCorrectness(PcapTestCase):
    def test_shuffled_duplicated_and_overlapping_fragments(self):
        rnd = random.Random(3)
        for trial in range(150):
            payload = bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(1, 6000)))
            l4 = udp(7000, 7001, payload)
            cuts = list(range(0, len(l4), 8))
            pieces, start = [], 0
            while start < len(l4):
                end = min(len(l4), start + 8 * rnd.randrange(1, 40))
                pieces.append((start, end))
                start = end
            if len(pieces) < 2:
                continue  # 1 片だけだとフラグメントではなく通常のデータグラム(重複を送ると 2 件になる)
            extras = []
            for _ in range(rnd.randrange(0, 5)):  # 重なる断片(中身は同じバイト列)
                a = rnd.choice(cuts)
                b = min(len(l4), a + 8 * rnd.randrange(1, 40))
                if a == 0 and b == len(l4):
                    continue  # 全体を 1 つで覆うとフラグメントではなく通常のデータグラムになる
                extras.append((a, b))
            order = pieces + extras + [rnd.choice(pieces)]
            rnd.shuffle(order)
            pkts = []
            for i, (a, b) in enumerate(order):
                more = 0x2000 if b < len(l4) else 0
                pkts.append((ms(i), ip4(C, S, 17, l4[a:b], ident=trial, frag_field=more | (a // 8))))
            rec, proc = self.run_pcap(make_pcap(pkts))
            # 再構成後に残った断片が合わせて全体を覆い直すと、同じ内容がもう一度出ることがある
            # (正しい挙動)。守りたいのは「出力が 1 件以上あり、すべて元のペイロードと一致する」こと。
            got = [d[1] for d in rec.datagrams]
            self.assertTrue(got, trial)
            self.assertTrue(all(item == payload for item in got), trial)


# ---------------------------------------------------------------------------
# TCP 再構成のランダム検証(並べ替え・重複・重なり・シーケンス番号の一周)
# ---------------------------------------------------------------------------
class TestTcpRoundTrip(PcapTestCase):
    def test_random_segmentation_round_trip(self):
        rnd = random.Random(12345)
        for trial in range(150):
            isn = rnd.choice([0, 1, 0xFFFFFF00, rnd.getrandbits(32), 0xFFFFFFFF - rnd.randrange(3000)])
            payload = bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(1, 6000)))
            segments, pos = [], 0
            while pos < len(payload):
                size = rnd.randrange(1, 1461)
                segments.append((pos, payload[pos:pos + size]))
                pos += size
            extra = [rnd.choice(segments) for _ in range(rnd.randrange(0, 6))]
            for _ in range(rnd.randrange(0, 4)):
                a = rnd.randrange(0, len(payload))
                extra.append((a, payload[a:a + rnd.randrange(1, 800)]))
            order = segments + extra
            rnd.shuffle(order)
            pkts = [tcp_pkt(0, C, 1234, S, 80, isn, 0, SYN)]
            for i, (offset, chunk) in enumerate(order):
                pkts.append(tcp_pkt(1 + i, C, 1234, S, 80, isn + 1 + offset, 0, ACK, chunk))
            end = 1 + len(order)
            pkts.append(tcp_pkt(end, C, 1234, S, 80, isn + 1 + len(payload), 0, FIN | ACK))
            pkts.append(tcp_pkt(end + 1, S, 80, C, 1234, 5, 0, FIN | ACK))
            rec, _ = self.run_pcap(make_pcap(pkts))
            self.assertEqual(len(rec.streams), 1, trial)
            self.assertEqual(rec.streams[0][1], payload, trial)
            self.assertEqual(rec.streams[0][2].gaps, [], trial)
            self.assertEqual(rec.streams[0][2].evict_reason, P.EVICT_FIN, trial)


# ---------------------------------------------------------------------------
# 新規接続の判定(ポート再利用)
# ---------------------------------------------------------------------------
class TestNewConnectionDetection(PcapTestCase):
    @staticmethod
    def _server_first_session(t0, client_isn, server_isn, banner):
        return [
            tcp_pkt(t0, C, 40000, S, 25, client_isn, 0, SYN),
            tcp_pkt(t0 + 1, S, 25, C, 40000, server_isn, client_isn + 1, SYN | ACK),
            tcp_pkt(t0 + 2, S, 25, C, 40000, server_isn + 1, client_isn + 1, PSH | ACK, banner),
        ]

    def test_reused_four_tuple_with_server_first_protocol_is_split(self):
        """SYN を送る側(クライアント)に未送信のデータがなくても、前の接続のデータがあれば別接続。"""
        pkts = (
            self._server_first_session(0, 1000, 6000, b"220 first\r\n")
            + self._server_first_session(10_000, 900_000, 700_000, b"220 second\r\n")
        )
        rec, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual([c.server.data for c in rec.convs], [b"220 first\r\n", b"220 second\r\n"])
        self.assertEqual(rec.convs[0].evict_reason, P.EVICT_NEW_CONNECTION)

    def test_syn_retransmission_is_not_a_new_connection(self):
        pkts = self._server_first_session(0, 1000, 6000, b"220 hello\r\n")
        pkts.insert(1, tcp_pkt(500, C, 40000, S, 25, 1000, 0, SYN))  # 同じ ISN の SYN 再送
        pkts.append(tcp_pkt(900, C, 40000, S, 25, 1000, 0, SYN))     # バナー後に遅れて届いた重複 SYN
        rec, _ = self.run_pcap(make_pcap(pkts))
        self.assertEqual(len(rec.convs), 1)
        self.assertEqual(rec.convs[0].server.data, b"220 hello\r\n")

    def test_new_syn_after_handshake_only_connection(self):
        pkts = [
            tcp_pkt(0, C, 40000, S, 25, 1000, 0, SYN),
            tcp_pkt(1, S, 25, C, 40000, 6000, 1001, SYN | ACK),
            tcp_pkt(10_000, C, 40000, S, 25, 55555, 0, SYN),
            tcp_pkt(10_001, S, 25, C, 40000, 77777, 55556, SYN | ACK),
            tcp_pkt(10_002, C, 40000, S, 25, 55556, 77778, PSH | ACK, b"hi"),
        ]
        rec, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual([c.client.data for c in rec.convs], [b"hi"])
        self.assertEqual(proc.stats["tcp_conversations"], 2)


# ---------------------------------------------------------------------------
# 半クローズと late パケット
# ---------------------------------------------------------------------------
class TestHalfCloseAndLate(PcapTestCase):
    def _unanswered_half_close(self):
        return [
            tcp_pkt(0, C, 1234, S, 80, 1000, 0, SYN),
            tcp_pkt(1, S, 80, C, 1234, 5000, 1001, SYN | ACK),
            tcp_pkt(2, C, 1234, S, 80, 1001, 5001, PSH | ACK, b"req"),
            tcp_pkt(3, C, 1234, S, 80, 1004, 5001, FIN | ACK),
            udp_pkt(60_000, "10.9.9.9", 1, "10.9.9.8", 2, b"x"),  # 60 秒後に別の通信
        ]

    def test_unanswered_half_close_stays_until_flush(self):
        rec, _ = self.run_pcap(make_pcap(self._unanswered_half_close()))
        self.assertEqual(rec.convs[0].evict_reason, P.EVICT_FLUSH)

    def test_unanswered_half_close_is_evicted_by_idle_timeout(self):
        rec, _ = self.run_pcap(make_pcap(self._unanswered_half_close()), idle_timeout=10)
        self.assertEqual(rec.convs[0].evict_reason, P.EVICT_IDLE)

    def test_final_ack_is_counted_as_late_ack_not_late_packet(self):
        _, proc = self.run_pcap(make_pcap(http_like_session()))
        self.assertEqual(proc.stats["late_acks"], 1)
        self.assertEqual(proc.stats["late_packets"], 0)

    def test_data_after_close_is_counted_as_late_packet(self):
        pkts = http_like_session()
        pkts.append(tcp_pkt(50, C, 1234, S, 80, 1001, 5001, PSH | ACK, b"stray"))
        _, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual(proc.stats["late_packets"], 1)


# ---------------------------------------------------------------------------
# エラー・入力
# ---------------------------------------------------------------------------
class TestErrorsAndInputs(PcapTestCase):
    def test_pcapng_error_has_hint_and_keeps_old_message_and_type(self):
        path = self.write_pcap(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        with self.assertRaises(P.PcapFormatError) as ctx:
            P.PcapStreamProcessor().process_file(path)
        text = str(ctx.exception)
        self.assertIsInstance(ctx.exception, ValueError)
        self.assertIn("Invalid pcap global header", text)
        self.assertIn("pcapng", text)
        self.assertIn("editcap", text)
        self.assertIn(path, text)

    def test_gzip_error_has_hint(self):
        with self.assertRaises(P.PcapFormatError) as ctx:
            self.run_pcap(b"\x1f\x8b" + b"\0" * 40)
        self.assertIn("gzip", str(ctx.exception))

    def test_unsupported_version_and_short_file(self):
        raw = bytearray(make_pcap(http_like_session()))
        raw[4:6] = struct.pack("<H", 3)
        with self.assertRaises(P.PcapFormatError) as ctx:
            self.run_pcap(bytes(raw))
        self.assertIn("unsupported pcap version", str(ctx.exception))
        with self.assertRaises(P.PcapFormatError) as ctx:
            self.run_pcap(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a")
        self.assertIn("too short", str(ctx.exception))

    def test_process_stream_accepts_file_like_objects(self):
        rec = Recorder()
        P.PcapStreamProcessor(analyzers=[rec]).process_stream(io.BytesIO(make_pcap(http_like_session())), name="mem")
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")
        with self.assertRaises(P.PcapFormatError) as ctx:
            P.PcapStreamProcessor().process_stream(io.BytesIO(b"x" * 40), name="mem")
        self.assertIn("mem", str(ctx.exception))

    def test_gzip_compressed_capture_via_process_stream(self):
        import gzip

        path = os.path.join(self.tmpdir, "capture.pcap.gz") if hasattr(self, "tmpdir") else None
        if path is None:
            import tempfile
            path = os.path.join(tempfile.mkdtemp(), "capture.pcap.gz")
        with gzip.open(path, "wb") as handle:
            handle.write(make_pcap(http_like_session()))
        rec = Recorder()
        with gzip.open(path, "rb") as handle:
            P.PcapStreamProcessor(analyzers=[rec]).process_stream(handle, name=path)
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")

    def test_process_file_accepts_pathlib_path(self):
        rec = Recorder()
        path = pathlib.Path(self.write_pcap(make_pcap(http_like_session())))
        P.PcapStreamProcessor(analyzers=[rec]).process_file(path)
        self.assertEqual(rec.convs[0].client.data, REQ)

    def test_warnings_include_the_file_name(self):
        path = self.write_pcap(make_pcap(http_like_session())[:-10])
        with self.assertLogs("pcapreasm", level="WARNING") as logs:
            P.PcapStreamProcessor().process_file(path)
        self.assertTrue(any(path in line for line in logs.output), logs.output)

    def test_process_files_default_still_raises_and_does_not_complete(self):
        good = self.write_pcap(make_pcap(http_like_session()))
        bad = self.write_pcap(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        rec = Recorder()
        with self.assertRaises(ValueError):
            P.PcapStreamProcessor(analyzers=[rec]).process_files([good, bad, good])
        self.assertEqual(rec.completed, 0)

    def test_process_files_skip_continues_and_flushes(self):
        pkts = http_like_session()
        first = self.write_pcap(make_pcap(pkts[:5]))
        bad = self.write_pcap(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        second = self.write_pcap(make_pcap(pkts[5:]))
        missing = os.path.join(os.path.dirname(first), "missing.pcap")
        rec = Recorder()
        proc = P.PcapStreamProcessor(analyzers=[rec])
        with self.assertLogs("pcapreasm", level="WARNING"):
            proc.process_files([first, bad, missing, second], on_error="skip")
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")  # 状態はファイルをまたいで保たれる
        self.assertEqual(proc.stats["failed_files"], 2)
        self.assertEqual(rec.completed, 1)

    def test_process_files_skip_still_flushes_when_last_file_fails(self):
        good = self.write_pcap(make_pcap([tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"data")]))
        bad = self.write_pcap(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        rec = Recorder()
        with self.assertLogs("pcapreasm", level="WARNING"):
            P.PcapStreamProcessor(analyzers=[rec]).process_files([good, bad], on_error="skip")
        self.assertEqual([s[1] for s in rec.streams], [b"data"])
        self.assertEqual(rec.completed, 1)

    def test_process_files_rejects_unknown_on_error(self):
        with self.assertRaises(ValueError):
            P.PcapStreamProcessor().process_files([], on_error="ignore")


class TestCallbacks(PcapTestCase):
    def test_file_start_and_end_wrap_each_file(self):
        events = []

        class Events(P.BaseAnalyzer):
            def on_file_start(self, path):
                events.append(("start", os.path.basename(path)))

            def on_file_end(self, path):
                events.append(("end", os.path.basename(path)))

            def on_complete(self):
                events.append(("complete",))

        pkts = http_like_session()
        first = self.write_pcap(make_pcap(pkts[:5]))
        second = self.write_pcap(make_pcap(pkts[5:]))
        P.PcapStreamProcessor(analyzers=[Events()]).process_files([first, second])
        b1, b2 = os.path.basename(first), os.path.basename(second)
        self.assertEqual(events, [("start", b1), ("end", b1), ("start", b2), ("end", b2), ("complete",)])

    def test_file_end_is_called_even_when_the_file_is_invalid(self):
        events = []

        class Events(P.BaseAnalyzer):
            def on_file_start(self, path):
                events.append("start")

            def on_file_end(self, path):
                events.append("end")

        with self.assertRaises(P.PcapFormatError):
            P.PcapStreamProcessor(analyzers=[Events()]).process_stream(io.BytesIO(b"x" * 40))
        self.assertEqual(events, ["start", "end"])

    def test_raise_on_analyzer_error(self):
        class Boom(P.BaseAnalyzer):
            def on_tcp_stream(self, *args):
                raise RuntimeError("boom")

        processor = P.PcapStreamProcessor(analyzers=[Boom()], raise_on_analyzer_error=True)
        with self.assertRaises(P.AnalyzerError) as ctx:
            processor.process_file(self.write_pcap(make_pcap(http_like_session())))
        self.assertIsInstance(ctx.exception.__cause__, RuntimeError)

    def test_analyzer_errors_are_still_swallowed_by_default(self):
        class Boom(P.BaseAnalyzer):
            def on_complete(self):
                raise RuntimeError("boom")

        with self.assertLogs("pcapreasm", level="ERROR"):
            P.PcapStreamProcessor(analyzers=[Boom()]).process_file(self.write_pcap(make_pcap(http_like_session())))


# ---------------------------------------------------------------------------
# 統計・メタ情報・snaplen
# ---------------------------------------------------------------------------
class TestStatsAndMeta(PcapTestCase):
    def test_conversation_and_eviction_counters(self):
        _, proc = self.run_pcap(make_pcap(http_like_session()))
        self.assertEqual(proc.stats["tcp_conversations"], 1)
        self.assertEqual(proc.stats["evict_fin"], 1)

    def test_snaplen_truncated_segment_is_reported(self):
        full = ip4(C, S, 6, tcp(1234, 80, 1001, 0, ACK, b"A" * 1000))
        cut = full[:20 + 20 + 100]  # IP の全長は 1040 のままで、先頭 140 バイトしか捕捉していない
        pkts = [
            (ms(0), cut),
            tcp_pkt(1, C, 1234, S, 80, 2001, 0, ACK, b"B" * 10),
        ]
        rec, proc = self.run_pcap(make_pcap(pkts))
        stream = rec.streams[0]
        self.assertEqual(proc.stats["truncated_packets"], 1)
        self.assertEqual(stream[2].truncated_segments, 1)
        self.assertEqual(stream[2].gaps, [(100, 900)])  # 欠損に見えるが、原因は切り詰め
        self.assertEqual(stream[1], b"A" * 100 + b"B" * 10)

    def test_tso_style_zero_total_length_is_not_truncation(self):
        packet = bytearray(ip4(C, S, 6, tcp(1234, 80, 1001, 0, ACK, b"A" * 50)))
        packet[2:4] = b"\0\0"  # TSO/GSO では IP 全長が 0 になる
        rec, proc = self.run_pcap(make_pcap([(ms(0), bytes(packet))]))
        self.assertEqual(proc.stats["truncated_packets"], 0)
        self.assertEqual(rec.streams[0][1], b"A" * 50)

    def test_ipv6_truncation_is_detected(self):
        full = ip6("2001:db8::1", "2001:db8::2", 17, udp(1, 2, b"x" * 200))
        wrap = lambda ip: (b"\0" * 12 + b"\x86\xdd" + ip)  # noqa: E731
        _, proc = self.run_pcap(make_pcap([(ms(0), full[:100])], wrap=wrap))
        self.assertEqual(proc.stats["truncated_packets"], 1)


# ---------------------------------------------------------------------------
# メモリ制御
# ---------------------------------------------------------------------------
class TestSegmentOverhead(PcapTestCase):
    PKTS = [
        tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"0123456789"),
        tcp_pkt(1, C, 1111, S, 80, 1010, 0, PSH | ACK, b"0123456789"),
    ]

    def test_default_counts_payload_only(self):
        rec, _ = self.run_pcap(make_pcap(self.PKTS), max_conversation_bytes=1500)
        self.assertNotIn(P.EVICT_MAX_BYTES, [s[2].evict_reason for s in rec.streams])

    def test_overhead_makes_small_segments_count_more(self):
        rec, _ = self.run_pcap(make_pcap(self.PKTS), max_conversation_bytes=1500, segment_overhead_bytes=1000)
        self.assertIn(P.EVICT_MAX_BYTES, [s[2].evict_reason for s in rec.streams])

    def test_negative_overhead_is_rejected(self):
        with self.assertRaises(ValueError):
            P.PcapStreamProcessor(segment_overhead_bytes=-1)


# ---------------------------------------------------------------------------
# ファズ(壊れた入力で想定外の例外を出さないこと)
# ---------------------------------------------------------------------------
class TestMutationFuzz(unittest.TestCase):
    def test_random_byte_flips_never_raise_unexpectedly(self):
        sessions = http_like_session() + http_like_session(cport=4321)
        sessions += [udp_pkt(30, C, 5000, S, 53, b"q"), (ms(31), ip4(C, S, 17, b"Z" * 24, ident=9, frag_field=0x2000))]
        seed = make_pcap(sessions)
        rnd = random.Random(99)
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        for _ in range(600):
            data = bytearray(seed)
            for _ in range(rnd.randrange(1, 40)):
                data[rnd.randrange(24, len(data))] = rnd.randrange(256)
            if rnd.random() < 0.3:
                del data[rnd.randrange(24, len(data)):]
            processor = P.PcapStreamProcessor(analyzers=[Recorder()], filter_expr="tcp or udp")
            processor.process_stream(io.BytesIO(bytes(data)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
