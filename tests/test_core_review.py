# SPDX-License-Identifier: MPL-2.0
"""0.2.2: コア部分の独立レビューで見つかった不具合の回帰テスト(時刻・シーケンス番号・フラグメント・FIN 後の CPU)。"""

import os
import random
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import pcapreasm as P  # noqa: E402
from test_pcapreasm import (  # noqa: E402
    ACK, C, FIN, PSH, S, SYN, PcapTestCase, ip4, make_pcap, tcp_pkt, udp_pkt,
)

SECOND = 1_000_000_000
SLOW_LIMIT_SECONDS = 8.0


def at(seconds, pkt):
    """(時刻, データ) のパケットの時刻を秒で置き換える。"""
    return (int(seconds * SECOND), pkt[1])


class TestClockIsNotAHighWaterMark(PcapTestCase):
    def test_one_far_future_packet_does_not_stop_idle_sweeps(self):
        pkts = [at(100_000, udp_pkt(0, C, 9, S, 9, b"x"))]  # 時計が大きく進んだ 1 パケット
        for index, t in enumerate((100, 101, 500, 900)):
            pkts.append(at(t, tcp_pkt(0, C, 1111, S, 80, 1000 + index * 4, 0, PSH | ACK, b"data")))
        rec, proc = self.run_pcap(make_pcap(pkts), idle_timeout=10)
        reasons = [s[2].evict_reason for s in rec.streams]
        self.assertGreaterEqual(reasons.count(P.EVICT_IDLE), 2, reasons)

    def test_second_file_with_earlier_timestamps_is_still_swept(self):
        first = make_pcap([at(1_000_000, udp_pkt(0, C, 9, S, 9, b"x"))])
        second = make_pcap([
            at(10, tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"a")),
            at(500, tcp_pkt(0, C, 2222, S, 80, 1000, 0, PSH | ACK, b"b")),
        ])
        rec = __import__("test_pcapreasm").Recorder()
        proc = P.PcapStreamProcessor(analyzers=[rec], idle_timeout=10)
        proc.process_files([self.write_pcap(first), self.write_pcap(second)])
        reasons = {s[1]: s[2].evict_reason for s in rec.streams}
        self.assertEqual(reasons[b"a"], P.EVICT_IDLE)


class TestSkewedClocksAreNotQuadratic(PcapTestCase):
    def test_timestamps_alternating_between_two_clocks_do_not_sweep_on_every_packet(self):
        # Half-closed conversations stay buffered; a sweep walks all of them.
        pkts = []
        for index in range(4000):
            port = 10_000 + index
            pkts += [
                at(0, tcp_pkt(0, C, port, S, 80, 1000, 0, SYN)),
                at(0, tcp_pkt(0, S, 80, C, port, 5000, 1001, SYN | ACK)),
                at(0, tcp_pkt(0, C, port, S, 80, 1001, 5001, PSH | ACK, b"data")),
                at(0, tcp_pkt(0, C, port, S, 80, 1010, 5001, FIN | ACK)),  # gap 1005..1009: never completes
            ]
        for index in range(15_000):
            pkts.append(at(10 + (5 if index % 2 else 0), udp_pkt(0, C, 9, S, 9, b"x")))
        started = time.perf_counter()
        _, proc = self.run_pcap(make_pcap(pkts))
        self.assertLess(time.perf_counter() - started, SLOW_LIMIT_SECONDS)
        self.assertEqual(proc.stats["packets"], len(pkts))


class TestSequenceUnwrapping(PcapTestCase):
    def test_junk_packets_do_not_shift_later_data_by_2_to_the_32(self):
        base = 1000
        pkts = [
            tcp_pkt(0, C, 1111, S, 80, base, 0, SYN),
            tcp_pkt(1, C, 1111, S, 80, base + 1, 0, PSH | ACK, b"AAAA"),
            tcp_pkt(2, C, 1111, S, 80, base + 1 + 0x70000000, 0, ACK),
            tcp_pkt(3, C, 1111, S, 80, base + 1 + 0xE0000000, 0, ACK),
            tcp_pkt(4, C, 1111, S, 80, base + 5, 0, PSH | ACK, b"BBBB"),
            tcp_pkt(5, C, 1111, S, 80, base + 9, 0, FIN | ACK),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        stream = [s for s in rec.streams if s[1]][0]
        self.assertEqual(stream[1], b"AAAABBBB")
        self.assertEqual(stream[2].gaps, [])

    def test_wraparound_still_works(self):
        isn = 0xFFFFFFF0
        pkts = [
            tcp_pkt(0, C, 1111, S, 80, isn, 0, SYN),
            tcp_pkt(1, C, 1111, S, 80, (isn + 1) & 0xFFFFFFFF, 0, PSH | ACK, b"X" * 20),
            tcp_pkt(2, C, 1111, S, 80, (isn + 21) & 0xFFFFFFFF, 0, PSH | ACK, b"Y" * 20),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts))
        stream = [s for s in rec.streams if s[1]][0]
        self.assertEqual(stream[1], b"X" * 20 + b"Y" * 20)


class TestFragmentsAndIpLength(PcapTestCase):
    def test_fragment_set_with_too_many_pieces_is_dropped(self):
        pkts = [
            (0, ip4(C, S, 17, b"A" * 8, ident=7, frag_field=0x2000 | (2 * i))) for i in range(P.FRAG_MAX_PIECES + 5)
        ]
        _, proc = self.run_pcap(make_pcap(pkts))
        self.assertEqual(proc.stats["frag_too_many_pieces"], 1)

    def test_a_normal_many_piece_datagram_still_assembles(self):
        payload = b"".join(bytes([i % 251]) * 8 for i in range(1000))
        l4 = b"\x13\x88\x00\x35" + (8 + len(payload)).to_bytes(2, "big") + b"\0\0" + payload
        pkts = []
        for i in range(0, len(l4), 8):
            more = 0x2000 if i + 8 < len(l4) else 0
            pkts.append((i, ip4(C, S, 17, l4[i:i + 8], ident=3, frag_field=more | (i // 8))))
        from test_pcapreasm import Recorder
        rec = Recorder()
        proc = P.PcapStreamProcessor(analyzers=[rec])
        proc.process_file(self.write_pcap(make_pcap(pkts)))
        self.assertEqual(len(rec.datagrams), 1)

    def test_ip_total_length_below_header_length_is_malformed(self):
        header = bytearray(ip4(C, S, 6, b"\0" * 20)[:20])
        header[2:4] = (10).to_bytes(2, "big")
        self.assertIsNone(P._parse_ipv4(bytes(header) + b"\0" * 20))


class TestContiguousCover(unittest.TestCase):
    @staticmethod
    def reference(chunks, start_seq, fin_seq):
        cover = P._Intervals()
        for seq, payload, _ in chunks:
            cover.add(seq, seq + len(payload))
        base = start_seq if start_seq is not None else (cover.starts[0] if cover.starts else fin_seq)
        return cover.reach(base) >= fin_seq

    def test_matches_the_interval_implementation_on_random_input(self):
        rnd = random.Random(7)
        for _ in range(3000):
            start = rnd.choice([None, 100])
            chunks = [(rnd.randint(95, 130), b"x" * rnd.randint(0, 6), 0) for _ in range(rnd.randint(0, 8))]
            fin = rnd.randint(95, 140)
            reassembler = P._TCPReassembler()
            reassembler.start_seq, reassembler.fin_seq = start, fin
            for index, chunk in enumerate(chunks):
                reassembler.chunks.append(chunk)
                self.assertEqual(
                    reassembler._covers_up_to_fin(), self.reference(chunks[: index + 1], start, fin),
                    (start, fin, chunks[: index + 1]),
                )

    def test_descending_segments_after_fin_are_not_quadratic(self):
        n = 100_000
        reassembler = P._TCPReassembler()
        reassembler.start_seq, reassembler.fin_seq = 1, 2 * n + 10
        started = time.perf_counter()
        for k in range(n, 0, -1):
            reassembler.chunks.append((1 + 2 * k, b"x", 0))
            reassembler._finished_cache = None
            reassembler.is_finished()
        self.assertLess(time.perf_counter() - started, SLOW_LIMIT_SECONDS)


if __name__ == "__main__":
    unittest.main()
