# SPDX-License-Identifier: MPL-2.0
"""pcapreasm 検証スクリプト。

実データは使わず、テスト内でバイト列から PCAP を合成して検証します
(公開リポジトリに置いても安全です)。標準ライブラリの unittest のみ使用。

実行方法(リポジトリのルートで):
    python -m unittest discover -s tests -v
pytest がある場合:
    pytest tests -v

TestKnownIssues は「現在わかっている問題」を記録するテストです。
問題が未修正の間は expectedFailure(期待どおりの失敗)として扱われ、
修正されると「unexpected success」になって知らせてくれます。
その場合は @unittest.expectedFailure を外してください。
"""

import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import pcapreasm as P  # noqa: E402

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
BASE_NS = 1_700_000_000 * 10**9
C, S = "10.0.0.1", "10.0.0.2"
REQ = b"GET / HTTP/1.0\r\n\r\n"


# ---------------------------------------------------------------------------
# パケット合成ヘルパー
# ---------------------------------------------------------------------------
def ms(n):
    """基準時刻から n ミリ秒後の timestamp_ns。"""
    return BASE_NS + n * 10**6


def ip4(src, dst, proto, payload, ident=1, frag_field=0):
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag_field, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return header + payload


def ip6(src, dst, next_header, payload):
    header = struct.pack(
        "!IHBB16s16s", 0x60000000, len(payload), next_header, 64,
        socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst),
    )
    return header + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0
    )
    return header + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp_pkt(t_ms, src, sport, dst, dport, seq, ack, flags, payload=b""):
    """(timestamp_ns, IP パケット) を返す。"""
    return ms(t_ms), ip4(src, dst, 6, tcp(sport, dport, seq, ack, flags, payload))


def udp_pkt(t_ms, src, sport, dst, dport, payload):
    return ms(t_ms), ip4(src, dst, 17, udp(sport, dport, payload))


def eth(ip_packet, vlan_tags=()):
    out = b"\0" * 12
    if vlan_tags:
        tpids = [0x8100] * len(vlan_tags)
        tpids[0] = 0x88A8 if len(vlan_tags) > 1 else 0x8100
        for tpid, tci in zip(tpids, vlan_tags):
            out += struct.pack("!HH", tpid, tci)
    out += struct.pack("!H", 0x0800)
    return out + ip_packet


def make_pcap(packets, wrap=eth, linktype=1, nano=False, big_endian=False):
    """packets: [(timestamp_ns, ip_packet)] からクラシック PCAP のバイト列を作る。"""
    endian = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
    for timestamp_ns, ip_packet in packets:
        data = wrap(ip_packet)
        sec, ns = divmod(timestamp_ns, 10**9)
        sub = ns if nano else ns // 1000
        out += struct.pack(endian + "IIII", sec, sub, len(data), len(data)) + data
    return bytes(out)


def http_like_session(server_isn=5000, server_order=(0, 1), duplicate_first=False, cport=1234):
    """3 ウェイハンドシェイク → 要求 → 応答 2 セグメント → 正常終了(FIN 交換)。

    サーバ応答は b"HELLO " + b"WORLD"(2 セグメント)。server_order で到着順を入れ替えられる。
    """
    a = server_isn + 1
    segments = [(a, b"HELLO "), (a + 6, b"WORLD")]
    ordered = [segments[i] for i in server_order]
    ack_of_req = 1001 + len(REQ)
    pkts = [
        tcp_pkt(0, C, cport, S, 80, 1000, 0, SYN),
        tcp_pkt(1, S, 80, C, cport, server_isn, 1001, SYN | ACK),
        tcp_pkt(2, C, cport, S, 80, 1001, a, ACK),
        tcp_pkt(3, C, cport, S, 80, 1001, a, PSH | ACK, REQ),
    ]
    t = 4
    for seq, payload in ordered:
        pkts.append(tcp_pkt(t, S, 80, C, cport, seq, ack_of_req, ACK, payload))
        t += 1
    if duplicate_first:
        pkts.append(tcp_pkt(t, S, 80, C, cport, segments[0][0], ack_of_req, ACK, segments[0][1]))
        t += 1
    pkts += [
        tcp_pkt(t, C, cport, S, 80, ack_of_req, a + 11, FIN | ACK),
        tcp_pkt(t + 1, S, 80, C, cport, a + 11, ack_of_req + 1, FIN | ACK),
        tcp_pkt(t + 2, C, cport, S, 80, ack_of_req + 1, a + 12, ACK),
    ]
    return pkts


class Recorder(P.BaseAnalyzer):
    """通知されたイベントをすべて記録する analyzer。"""

    def __init__(self):
        self.streams, self.convs, self.datagrams, self.udp_flows, self.completed = [], [], [], [], 0

    def on_tcp_stream(self, flow_id, data, meta):
        self.streams.append((flow_id, data, meta))

    def on_tcp_conversation(self, conversation):
        self.convs.append(conversation)

    def on_udp_datagram(self, flow_id, payload, timestamp_ns):
        self.datagrams.append((flow_id, payload, timestamp_ns))

    def on_udp_flow(self, flow_id, datagrams, meta):
        self.udp_flows.append((flow_id, datagrams, meta))

    def on_complete(self):
        self.completed += 1


class PcapTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._counter = 0

    def write_pcap(self, raw):
        self._counter += 1
        path = os.path.join(self._tmpdir.name, f"t{self._counter}.pcap")
        with open(path, "wb") as f:
            f.write(raw)
        return path

    def run_pcap(self, raw, **kwargs):
        recorder = Recorder()
        processor = P.PcapStreamProcessor(analyzers=[recorder], **kwargs)
        processor.process_file(self.write_pcap(raw))
        return recorder, processor


# ---------------------------------------------------------------------------
# TCP 再構成
# ---------------------------------------------------------------------------
class TestTcpReassembly(PcapTestCase):
    def test_basic_conversation(self):
        rec, proc = self.run_pcap(make_pcap(http_like_session()))
        self.assertEqual(len(rec.convs), 1)
        conv = rec.convs[0]
        self.assertEqual(conv.client.data, REQ)
        self.assertEqual(conv.server.data, b"HELLO WORLD")
        self.assertTrue(conv.client_certain)
        self.assertEqual(conv.evict_reason, P.EVICT_FIN)
        self.assertEqual(conv.client.flow_id, (C, 1234, S, 80))
        self.assertEqual(conv.server.flow_id, (S, 80, C, 1234))
        self.assertEqual(conv.server.meta.gap_count, 0)
        self.assertEqual(rec.completed, 1)

    def test_stream_callbacks_order_client_then_server(self):
        rec, _ = self.run_pcap(make_pcap(http_like_session()))
        self.assertEqual([s[0] for s in rec.streams], [(C, 1234, S, 80), (S, 80, C, 1234)])

    def test_out_of_order_and_duplicate_segments(self):
        pkts = http_like_session(server_order=(1, 0), duplicate_first=True)
        rec, _ = self.run_pcap(make_pcap(pkts))
        conv = rec.convs[0]
        self.assertEqual(conv.server.data, b"HELLO WORLD")
        self.assertEqual(conv.server.meta.retrans_count, 1)
        self.assertEqual(conv.evict_reason, P.EVICT_FIN)

    def test_sequence_number_wraparound(self):
        pkts = http_like_session(server_isn=0xFFFFFFFA, server_order=(1, 0))
        rec, _ = self.run_pcap(make_pcap(pkts))
        conv = rec.convs[0]
        self.assertEqual(conv.server.data, b"HELLO WORLD")
        self.assertEqual(conv.server.meta.gaps, [])

    def test_gap_is_recorded_and_not_padded(self):
        pkts = [
            tcp_pkt(0, C, 1234, S, 80, 1000, 0, SYN),
            tcp_pkt(1, S, 80, C, 1234, 5000, 1001, SYN | ACK),
            tcp_pkt(2, C, 1234, S, 80, 1001, 5001, ACK),
            tcp_pkt(3, S, 80, C, 1234, 5001, 1001, ACK, b"AAAA"),
            tcp_pkt(5, S, 80, C, 1234, 5009, 1001, ACK, b"CCCC"),  # 5005-5008 が欠損
            tcp_pkt(6, C, 1234, S, 80, 1001, 5013, FIN | ACK),
            tcp_pkt(7, S, 80, C, 1234, 5013, 1002, FIN | ACK),
            udp_pkt(20000, "10.9.9.9", 1, "10.9.9.8", 2, b"x"),  # 20 秒後: close_linger 超過で掃除される
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        conv = rec.convs[0]
        self.assertEqual(conv.server.data, b"AAAACCCC")  # 詰め物なし
        self.assertEqual(conv.server.meta.gaps, [(4, 4)])
        self.assertEqual(conv.server.meta.gap_bytes, 4)
        self.assertEqual(conv.evict_reason, P.EVICT_FIN_TIMEOUT)

    def test_timeline_concatenates_to_data(self):
        rec, _ = self.run_pcap(make_pcap(http_like_session(server_order=(1, 0))))
        server = rec.convs[0].server
        self.assertEqual(b"".join(chunk for _, chunk in server.meta.timeline), server.data)
        self.assertEqual([len(c) for _, c in server.meta.timeline], [6, 5])

    def test_rst_evicts_conversation(self):
        pkts = [
            tcp_pkt(0, C, 1234, S, 80, 1000, 0, SYN),
            tcp_pkt(1, S, 80, C, 1234, 5000, 1001, SYN | ACK),
            tcp_pkt(2, C, 1234, S, 80, 1001, 5001, PSH | ACK, b"abc"),
            tcp_pkt(3, S, 80, C, 1234, 5001, 1004, RST | ACK),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        self.assertEqual(rec.convs[0].evict_reason, P.EVICT_RST)
        self.assertEqual(rec.convs[0].client.data, b"abc")

    def test_new_syn_on_same_four_tuple_starts_new_conversation(self):
        pkts = [
            tcp_pkt(0, C, 1234, S, 80, 1000, 0, SYN),
            tcp_pkt(1, S, 80, C, 1234, 5000, 1001, SYN | ACK),
            tcp_pkt(2, C, 1234, S, 80, 1001, 5001, PSH | ACK, b"ONE"),
            tcp_pkt(10, C, 1234, S, 80, 9000, 0, SYN),  # 同じ 4 つ組で新しい接続
            tcp_pkt(11, S, 80, C, 1234, 7000, 9001, SYN | ACK),
            tcp_pkt(12, C, 1234, S, 80, 9001, 7001, PSH | ACK, b"TWO"),
            tcp_pkt(13, C, 1234, S, 80, 9004, 7001, FIN | ACK),
            tcp_pkt(14, S, 80, C, 1234, 7001, 9005, FIN | ACK),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        self.assertEqual([c.client.data for c in rec.convs], [b"ONE", b"TWO"])
        self.assertEqual(rec.convs[0].evict_reason, P.EVICT_NEW_CONNECTION)
        self.assertEqual(rec.convs[1].evict_reason, P.EVICT_FIN)

    def test_midstream_capture_guesses_client(self):
        """SYN が無い(途中から捕捉した)場合、最初のパケットの送信側を client と推定する。"""
        pkts = [
            tcp_pkt(0, C, 1234, S, 80, 1001, 5001, PSH | ACK, b"req"),
            tcp_pkt(1, S, 80, C, 1234, 5001, 1004, PSH | ACK, b"resp"),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        conv = rec.convs[0]
        self.assertFalse(conv.client_certain)
        self.assertEqual(conv.evict_reason, P.EVICT_FLUSH)
        self.assertEqual((conv.client.data, conv.server.data), (b"req", b"resp"))

    def test_orphan_ack_does_not_create_conversation(self):
        pkts = [tcp_pkt(0, C, 1234, S, 80, 1001, 5001, ACK)]
        rec, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual(rec.convs, [])
        self.assertEqual(proc.stats["orphan_packets"], 1)

    def test_evict_on_fin_false_waits_until_flush(self):
        rec, _ = self.run_pcap(make_pcap(http_like_session()), evict_on_fin=False)
        self.assertEqual(rec.convs[0].evict_reason, P.EVICT_FLUSH)
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")

    def test_nanosecond_timestamps_are_kept_as_integers(self):
        pkts = [(t + 123, ip) for t, ip in http_like_session()]
        rec, _ = self.run_pcap(make_pcap(pkts, nano=True))
        self.assertEqual(rec.convs[0].first_timestamp_ns, ms(0) + 123)
        self.assertIsInstance(rec.convs[0].first_timestamp_ns, int)


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------
class TestUdp(PcapTestCase):
    def test_datagrams_and_flow_batch(self):
        pkts = [udp_pkt(0, C, 5000, S, 53, b"q1"), udp_pkt(10, C, 5000, S, 53, b"q2")]
        rec, _ = self.run_pcap(make_pcap(pkts))
        self.assertEqual([d[1] for d in rec.datagrams], [b"q1", b"q2"])
        self.assertEqual(len(rec.udp_flows), 1)
        flow_id, datagrams, meta = rec.udp_flows[0]
        self.assertEqual(flow_id, (C, 5000, S, 53))
        self.assertEqual(meta.datagram_count, 2)
        self.assertEqual(meta.first_timestamp_ns, ms(0))
        self.assertEqual(meta.last_timestamp_ns, ms(10))

    def test_udp_flow_not_kept_unless_overridden(self):
        class DatagramOnly(P.BaseAnalyzer):
            pass

        processor = P.PcapStreamProcessor(analyzers=[DatagramOnly()])
        self.assertFalse(processor._keep_udp_flows)
        processor = P.PcapStreamProcessor(analyzers=[Recorder()])
        self.assertTrue(processor._keep_udp_flows)

    def test_ethernet_padding_is_trimmed(self):
        raw = make_pcap([udp_pkt(0, C, 5000, S, 53, b"hi")], wrap=lambda ip: eth(ip) + b"\0" * 10)
        rec, _ = self.run_pcap(raw)
        self.assertEqual(rec.datagrams[0][1], b"hi")


# ---------------------------------------------------------------------------
# IP フラグメント / IPv6
# ---------------------------------------------------------------------------
BIG_PAYLOAD = bytes(range(256)) * 11 + b"Z" * 184  # 3000 バイト


class TestFragmentsAndIPv6(PcapTestCase):
    def _ipv4_fragments(self):
        l4 = udp(7000, 7001, BIG_PAYLOAD)
        f1, f2, f3 = l4[:1480], l4[1480:2960], l4[2960:]
        return f1, f2, f3

    def test_ipv4_fragments_out_of_order(self):
        f1, f2, f3 = self._ipv4_fragments()
        pkts = [
            (ms(0), ip4(C, S, 17, f2, ident=77, frag_field=0x2000 | 185)),
            (ms(1), ip4(C, S, 17, f3, ident=77, frag_field=370)),
            (ms(2), ip4(C, S, 17, f1, ident=77, frag_field=0x2000)),
        ]
        rec, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual([d[1] for d in rec.datagrams], [BIG_PAYLOAD])
        self.assertEqual(proc.stats["frag_reassembled"], 1)

    def test_fragments_dropped_when_reassembly_disabled(self):
        f1, f2, f3 = self._ipv4_fragments()
        pkts = [
            (ms(0), ip4(C, S, 17, f1, ident=77, frag_field=0x2000)),
            (ms(1), ip4(C, S, 17, f2, ident=77, frag_field=0x2000 | 185)),
            (ms(2), ip4(C, S, 17, f3, ident=77, frag_field=370)),
        ]
        rec, proc = self.run_pcap(make_pcap(pkts), reassemble_fragments=False)
        self.assertEqual(rec.datagrams, [])
        self.assertEqual(proc.stats["fragments_dropped"], 3)

    def test_incomplete_fragments_are_counted_at_flush(self):
        f1, _, _ = self._ipv4_fragments()
        pkts = [(ms(0), ip4(C, S, 17, f1, ident=77, frag_field=0x2000))]
        rec, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual(rec.datagrams, [])
        self.assertEqual(proc.stats["frag_incomplete_at_flush"], 1)

    def test_ipv6_udp(self):
        src, dst = "2001:db8::1", "2001:db8::2"
        pkts = [(ms(0), ip6(src, dst, 17, udp(5000, 53, b"v6-query")))]
        rec, _ = self.run_pcap(make_pcap(pkts, wrap=lambda ip: eth(ip).replace(b"\x08\x00", b"\x86\xdd", 1)))
        self.assertEqual(rec.datagrams[0][0], (src, 5000, dst, 53))
        self.assertEqual(rec.datagrams[0][1], b"v6-query")

    def test_ipv6_fragments(self):
        src, dst = "2001:db8::1", "2001:db8::2"
        l4 = udp(7000, 7001, BIG_PAYLOAD)
        parts = [(0, l4[:1480], 1), (1480, l4[1480:2960], 1), (2960, l4[2960:], 0)]

        def frag(offset, chunk, more):
            header = struct.pack("!BBHI", 17, 0, ((offset // 8) << 3) | more, 0xABCD)
            return ip6(src, dst, 44, header + chunk)

        pkts = [(ms(i), frag(*parts[order])) for i, order in enumerate((2, 0, 1))]
        raw = make_pcap(pkts, wrap=lambda ip: eth(ip).replace(b"\x08\x00", b"\x86\xdd", 1))
        rec, proc = self.run_pcap(raw)
        self.assertEqual([d[1] for d in rec.datagrams], [BIG_PAYLOAD])
        self.assertEqual(proc.stats["frag_reassembled"], 1)


# ---------------------------------------------------------------------------
# リンクタイプ / PCAP 形式
# ---------------------------------------------------------------------------
class TestLinkTypesAndFormats(PcapTestCase):
    def assertSessionDecoded(self, raw, **kwargs):
        rec, proc = self.run_pcap(raw, **kwargs)
        self.assertTrue(rec.convs, dict(proc.stats))
        self.assertEqual(rec.convs[0].client.data, REQ)
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")

    def test_vlan(self):
        self.assertSessionDecoded(make_pcap(http_like_session(), wrap=lambda ip: eth(ip, vlan_tags=(100,))))

    def test_qinq(self):
        self.assertSessionDecoded(make_pcap(http_like_session(), wrap=lambda ip: eth(ip, vlan_tags=(5, 6))))

    def test_linux_sll(self):
        wrap = lambda ip: struct.pack("!HHH8sH", 0, 1, 6, b"\0" * 8, 0x0800) + ip  # noqa: E731
        self.assertSessionDecoded(make_pcap(http_like_session(), wrap=wrap, linktype=113))

    def test_linux_sll2(self):
        wrap = lambda ip: struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\0" * 8) + ip  # noqa: E731
        self.assertSessionDecoded(make_pcap(http_like_session(), wrap=wrap, linktype=276))

    def test_raw_ip(self):
        self.assertSessionDecoded(make_pcap(http_like_session(), wrap=lambda ip: ip, linktype=101))

    def test_bsd_loopback(self):
        wrap = lambda ip: struct.pack("<I", 2) + ip  # noqa: E731
        self.assertSessionDecoded(make_pcap(http_like_session(), wrap=wrap, linktype=0))

    def test_big_endian_pcap(self):
        self.assertSessionDecoded(make_pcap(http_like_session(), big_endian=True))

    def test_nanosecond_pcap(self):
        self.assertSessionDecoded(make_pcap(http_like_session(), nano=True))

    def test_unsupported_linktype_is_skipped_with_warning(self):
        raw = make_pcap(http_like_session(), linktype=147)
        with self.assertLogs("pcapreasm", level="WARNING"):
            rec, proc = self.run_pcap(raw)
        self.assertEqual(rec.convs, [])
        self.assertEqual(proc.stats["non_ip"], proc.stats["packets"])

    def test_non_ip_frame_is_counted(self):
        frame = b"\0" * 12 + struct.pack("!H", 0x0806) + b"\0" * 28  # ARP
        rec, proc = self.run_pcap(make_pcap([(ms(0), b"")], wrap=lambda _ip: frame))
        self.assertEqual(proc.stats["non_ip"], 1)

    def test_truncated_file_keeps_valid_records(self):
        raw = make_pcap(http_like_session())
        with self.assertLogs("pcapreasm", level="WARNING") as logs:
            rec, _ = self.run_pcap(raw[:-10])
        self.assertTrue(any("Truncated" in line for line in logs.output))
        self.assertTrue(rec.streams)

    def test_pcapng_is_rejected_with_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.run_pcap(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        self.assertIn("Invalid pcap global header", str(ctx.exception))

    def test_empty_file_is_tolerated(self):
        with self.assertLogs("pcapreasm", level="WARNING"):
            rec, _ = self.run_pcap(b"")
        self.assertEqual(rec.completed, 1)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            P.PcapStreamProcessor().process_file(os.path.join(self._tmpdir.name, "nope.pcap"))

    def test_state_is_carried_across_files(self):
        pkts = http_like_session()
        first = self.write_pcap(make_pcap(pkts[:5]))   # SYN ... 応答の 1 セグメント目まで
        second = self.write_pcap(make_pcap(pkts[5:]))  # 残り
        rec = Recorder()
        P.PcapStreamProcessor(analyzers=[rec]).process_files([first, second])
        self.assertEqual(len(rec.convs), 1)
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")
        self.assertEqual(rec.completed, 1)


# ---------------------------------------------------------------------------
# Analyzer / 上限
# ---------------------------------------------------------------------------
class TestAnalyzerAndLimits(PcapTestCase):
    def test_exception_in_one_analyzer_does_not_stop_others(self):
        class Boom(P.BaseAnalyzer):
            def on_tcp_stream(self, *args):
                raise RuntimeError("boom")

        recorder = Recorder()
        processor = P.PcapStreamProcessor(analyzers=[Boom(), recorder])
        with self.assertLogs("pcapreasm", level="ERROR"):
            processor.process_file(self.write_pcap(make_pcap(http_like_session())))
        self.assertEqual(len(recorder.convs), 1)
        self.assertEqual(recorder.completed, 1)

    def test_max_conversation_bytes(self):
        rec, _ = self.run_pcap(make_pcap(http_like_session()), max_conversation_bytes=10)
        self.assertIn(P.EVICT_MAX_BYTES, [s[2].evict_reason for s in rec.streams])

    def test_max_conversations_evicts_oldest(self):
        pkts = [
            tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"first"),
            tcp_pkt(1, C, 2222, S, 80, 1000, 0, PSH | ACK, b"second"),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts), max_conversations=1)
        reasons = {s[1]: s[2].evict_reason for s in rec.streams}
        self.assertEqual(reasons[b"first"], P.EVICT_MAX_CONVERSATIONS)
        self.assertEqual(reasons[b"second"], P.EVICT_FLUSH)

    def test_max_total_bytes_evicts_oldest(self):
        pkts = [
            tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"A" * 100),
            tcp_pkt(1, C, 2222, S, 80, 1000, 0, PSH | ACK, b"B" * 100),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts), max_total_bytes=150)
        reasons = {s[1][:1]: s[2].evict_reason for s in rec.streams}
        self.assertEqual(reasons[b"A"], P.EVICT_MAX_TOTAL_BYTES)
        self.assertEqual(reasons[b"B"], P.EVICT_FLUSH)

    def test_idle_timeout_uses_capture_time(self):
        pkts = [
            tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"idle-me"),
            udp_pkt(60_000, "10.9.9.9", 1, "10.9.9.8", 2, b"x"),  # キャプチャ時刻で 60 秒後
        ]
        rec, _ = self.run_pcap(make_pcap(pkts), idle_timeout=10)
        self.assertEqual(rec.streams[0][2].evict_reason, P.EVICT_IDLE)

    def test_invalid_max_conversations(self):
        with self.assertRaises(ValueError):
            P.PcapStreamProcessor(max_conversations=0)

    def test_ns_to_seconds(self):
        self.assertAlmostEqual(P.ns_to_seconds(1_500_000_000), 1.5)


# ---------------------------------------------------------------------------
# 現在わかっている問題(修正されるまでは expectedFailure)
# ---------------------------------------------------------------------------
class TestKnownIssues(PcapTestCase):
    @unittest.expectedFailure
    def test_half_close_longer_than_close_linger_keeps_one_conversation(self):
        """クライアントが FIN 後、サーバが close_linger(5 秒)超えて応答しても、
        1 つの会話としてクライアント/サーバの役割が保たれるべき。

        現状: fin_timeout で一度確定され、遅れて届いたサーバのデータが別会話になり、
        client_certain=False で役割が逆に割り当てられる。
        """
        pkts = [
            tcp_pkt(0, C, 1234, S, 80, 1000, 0, SYN),
            tcp_pkt(1, S, 80, C, 1234, 5000, 1001, SYN | ACK),
            tcp_pkt(2, C, 1234, S, 80, 1001, 5001, ACK),
            tcp_pkt(3, C, 1234, S, 80, 1001, 5001, FIN | ACK),
            tcp_pkt(10_000, S, 80, C, 1234, 5001, 1002, PSH | ACK, b"LATE-RESPONSE"),
            tcp_pkt(10_001, S, 80, C, 1234, 5014, 1002, FIN | ACK),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        self.assertEqual(len(rec.convs), 1)
        self.assertEqual(rec.convs[0].server.data, b"LATE-RESPONSE")
        self.assertEqual(rec.convs[0].server.flow_id, (S, 80, C, 1234))

    @unittest.expectedFailure
    def test_normal_close_does_not_count_late_packets(self):
        """正常終了(最後の ACK)が late_packets に数えられないべき。"""
        _, proc = self.run_pcap(make_pcap(http_like_session()))
        self.assertEqual(proc.stats["late_packets"], 0)

    @unittest.expectedFailure
    def test_pcapng_error_message_mentions_pcapng(self):
        """pcapng を渡したとき、エラーメッセージで pcapng 非対応だと分かるべき。"""
        with self.assertRaises(ValueError) as ctx:
            self.run_pcap(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        self.assertIn("pcapng", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
