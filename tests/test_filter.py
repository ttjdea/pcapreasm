# SPDX-License-Identifier: MPL-2.0
"""filter_expr / packet_filter(0.1.0 で追加)のテスト。

tcpdump が入っている環境では、tcpdump 自身の判定と突き合わせるテストも走ります
(入っていなければ自動でスキップされます)。
"""

import os
import random
import shutil
import socket
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import pcapreasm as P  # noqa: E402
from test_pcapreasm import (  # noqa: E402
    ACK, C, FIN, PSH, S, SYN, PcapTestCase,
    http_like_session, ip4, ip6, make_pcap, ms, tcp_pkt, udp, udp_pkt,
)

TCP, UDP = P.IPPROTO_TCP, P.IPPROTO_UDP


def raw(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return socket.inet_pton(family, address)


def check(expression, proto, src, sport, dst, dport):
    """`expression` が与えたパケット(アドレスは文字列)に一致するか。"""
    return compile_and_call(expression, proto, src, sport, dst, dport)


def compile_and_call(expression, proto, src, sport, dst, dport):
    return P.compile_filter(expression)(proto, raw(src), sport, raw(dst), dport)


class TestCompileFilter(unittest.TestCase):
    A, B = "10.0.0.1", "192.168.1.9"

    def test_protocol_only(self):
        self.assertTrue(check("tcp", TCP, self.A, 1, self.B, 2))
        self.assertFalse(check("tcp", UDP, self.A, 1, self.B, 2))
        self.assertTrue(check("udp", UDP, self.A, 1, self.B, 2))
        self.assertTrue(check("ip", TCP, self.A, 1, self.B, 2))
        self.assertFalse(check("ip6", TCP, self.A, 1, self.B, 2))
        self.assertTrue(check("ip6", UDP, "2001:db8::1", 1, "2001:db8::2", 2))
        self.assertFalse(check("ip", UDP, "2001:db8::1", 1, "2001:db8::2", 2))

    def test_port_matches_both_protocols_and_both_directions(self):
        for proto in (TCP, UDP):
            self.assertTrue(check("port 80", proto, self.A, 80, self.B, 5000))
            self.assertTrue(check("port 80", proto, self.A, 5000, self.B, 80))
            self.assertFalse(check("port 80", proto, self.A, 5000, self.B, 5001))

    def test_directional_ports(self):
        self.assertTrue(check("src port 80", TCP, self.A, 80, self.B, 5000))
        self.assertFalse(check("src port 80", TCP, self.A, 5000, self.B, 80))
        self.assertTrue(check("dst port 80", TCP, self.A, 5000, self.B, 80))
        self.assertFalse(check("dst port 80", TCP, self.A, 80, self.B, 5000))
        self.assertTrue(check("src or dst port 80", TCP, self.A, 5000, self.B, 80))
        self.assertTrue(check("src and dst port 80", TCP, self.A, 80, self.B, 80))
        self.assertFalse(check("src and dst port 80", TCP, self.A, 80, self.B, 81))

    def test_protocol_qualified_port(self):
        self.assertTrue(check("tcp port 80", TCP, self.A, 80, self.B, 1))
        self.assertFalse(check("tcp port 80", UDP, self.A, 80, self.B, 1))
        self.assertTrue(check("udp dst port 53", UDP, self.A, 1, self.B, 53))
        self.assertFalse(check("udp dst port 53", TCP, self.A, 1, self.B, 53))

    def test_portrange_is_inclusive(self):
        for port, expected in ((7999, False), (8000, True), (8050, True), (8100, True), (8101, False)):
            self.assertEqual(check("portrange 8000-8100", TCP, self.A, 1, self.B, port), expected, port)

    def test_host_and_net(self):
        self.assertTrue(check("host 10.0.0.1", TCP, self.A, 1, self.B, 2))
        self.assertTrue(check("host 192.168.1.9", TCP, self.A, 1, self.B, 2))
        self.assertFalse(check("host 10.0.0.2", TCP, self.A, 1, self.B, 2))
        self.assertTrue(check("src host 10.0.0.1", TCP, self.A, 1, self.B, 2))
        self.assertFalse(check("src host 192.168.1.9", TCP, self.A, 1, self.B, 2))
        self.assertTrue(check("dst net 192.168.0.0/16", TCP, self.A, 1, self.B, 2))
        self.assertFalse(check("src net 192.168.0.0/16", TCP, self.A, 1, self.B, 2))
        self.assertTrue(check("net 10.0.0.0/8", TCP, self.A, 1, self.B, 2))
        self.assertFalse(check("net 172.16.0.0/12", TCP, self.A, 1, self.B, 2))

    def test_ipv6_host_and_net_do_not_match_ipv4(self):
        v6a, v6b = "2001:db8::1", "2001:db8:1::2"
        self.assertTrue(check("host 2001:db8::1", UDP, v6a, 1, v6b, 2))
        self.assertTrue(check("net 2001:db8::/32", UDP, v6a, 1, v6b, 2))
        self.assertFalse(check("net 2001:db9::/32", UDP, v6a, 1, v6b, 2))
        self.assertFalse(check("net 2001:db8::/32", UDP, self.A, 1, self.B, 2))
        self.assertFalse(check("net 0.0.0.0/0", UDP, v6a, 1, v6b, 2))
        self.assertTrue(check("net 0.0.0.0/0", UDP, self.A, 1, self.B, 2))

    def test_logical_operators_and_parentheses(self):
        pkt = (TCP, self.A, 80, self.B, 5000)
        self.assertTrue(check("tcp and port 80", *pkt))
        self.assertTrue(check("tcp && port 80", *pkt))
        self.assertFalse(check("tcp and port 81", *pkt))
        self.assertTrue(check("port 81 or port 80", *pkt))
        self.assertTrue(check("port 81 || port 80", *pkt))
        self.assertFalse(check("not port 80", *pkt))
        self.assertFalse(check("!port 80", *pkt))
        self.assertTrue(check("not (port 81 or port 82)", *pkt))
        self.assertTrue(check("tcp and (port 81 or port 80)", *pkt))
        self.assertFalse(check("tcp and not (port 81 or port 80)", *pkt))
        self.assertTrue(check("port 80 and not host 10.0.0.2", *pkt))
        self.assertFalse(check("port 80 and not host 10.0.0.1", *pkt))
        self.assertTrue(check("not not tcp", *pkt))
        self.assertTrue(check("TCP AND PORT 80", *pkt))  # 大文字小文字は区別しない

    def test_omitted_qualifiers_repeat_the_previous_ones(self):
        """tcpdump と同様、`port 80 or 443` は `port 80 or port 443`、`host a or b` も同じ。"""
        self.assertTrue(check("port 80 or 443", TCP, self.A, 443, self.B, 1))
        self.assertFalse(check("port 80 or 443", TCP, self.A, 444, self.B, 1))
        self.assertTrue(check("tcp dst port 80 or 443", TCP, self.A, 1, self.B, 443))
        self.assertFalse(check("tcp dst port 80 or 443", TCP, self.A, 443, self.B, 1))
        self.assertTrue(check("host 10.0.0.9 or 192.168.1.9", TCP, self.A, 1, self.B, 2))

    def test_empty_expression_matches_everything(self):
        self.assertTrue(check("", TCP, self.A, 1, self.B, 2))
        self.assertTrue(check("   ", UDP, self.A, 1, self.B, 2))

    def test_syntax_errors_and_unsupported_constructs_raise(self):
        bad = [
            "port",                       # 値がない
            "port 80 and",                # 演算子の後ろがない
            "and port 80",
            "(port 80",                   # 括弧が閉じていない
            "port 80)",
            "port 80 port 81",            # 演算子がない
            "port http",                  # サービス名は未対応
            "port 70000",                 # 範囲外
            "portrange 80",               # 範囲の形式でない
            "portrange 90-80",
            "host example.com",           # ホスト名の解決はしない
            "host 10.0.0.300",
            "net 10.0.0.0",               # CIDR 必須
            "net 10.0.0.1/8",             # ホストビットが立っている
            "vlan",                       # 未対応
            "vlan 100",
            "ether host 00:11:22:33:44:55",
            "tcp[13] & 2 != 0",           # バイト位置指定は未対応
            "greater 100",
            "icmp",
            "port 80 ; port 81",
            "port 80 & 81",
            "tcp and port 80 or port 81",  # and/or の混在は括弧が必要
            "port 80 or port 81 and tcp",
        ]
        for expression in bad:
            with self.subTest(expression=expression):
                with self.assertRaises(P.FilterSyntaxError):
                    P.compile_filter(expression)

    def test_filter_syntax_error_is_a_value_error(self):
        with self.assertRaises(ValueError):
            P.compile_filter("vlan")

    def test_same_operator_can_chain(self):
        self.assertTrue(check("port 1 or port 2 or port 80", TCP, self.A, 80, self.B, 9))
        self.assertFalse(check("tcp and port 80 and host 10.0.0.2", TCP, self.A, 80, self.B, 9))


def session(cport, sport, t0=0, body=b"HELLO WORLD"):
    """サーバのポートを指定できる小さな TCP セッション(ハンドシェイク→要求→応答→FIN 交換)。"""
    a = 5001
    return [
        tcp_pkt(t0, C, cport, S, sport, 1000, 0, SYN),
        tcp_pkt(t0 + 1, S, sport, C, cport, 5000, 1001, SYN | ACK),
        tcp_pkt(t0 + 2, C, cport, S, sport, 1001, a, PSH | ACK, b"GET /"),
        tcp_pkt(t0 + 3, S, sport, C, cport, a, 1006, PSH | ACK, body),
        tcp_pkt(t0 + 4, C, cport, S, sport, 1006, a + len(body), FIN | ACK),
        tcp_pkt(t0 + 5, S, sport, C, cport, a + len(body), 1007, FIN | ACK),
        tcp_pkt(t0 + 6, C, cport, S, sport, 1007, a + len(body) + 1, ACK),
    ]


class TestFilterInProcessor(PcapTestCase):
    def two_sessions(self):
        return session(1234, 80) + session(4321, 8080, t0=10)

    def test_filter_expr_drops_other_flows_before_any_state_is_kept(self):
        rec, proc = self.run_pcap(make_pcap(self.two_sessions()), filter_expr="port 8080")
        self.assertEqual(len(rec.convs), 1)
        self.assertEqual(rec.convs[0].client.data, b"GET /")
        self.assertEqual(proc.stats["tcp_conversations"], 1)
        self.assertEqual(proc.stats["filtered"], 7)  # 80 番のセッションの 7 パケットが落ちる

    def test_no_filter_keeps_everything_and_counts_nothing_filtered(self):
        rec, proc = self.run_pcap(make_pcap(self.two_sessions()))
        self.assertEqual(len(rec.convs), 2)
        self.assertEqual(proc.stats["filtered"], 0)

    def test_empty_expression_is_no_filter(self):
        rec, proc = self.run_pcap(make_pcap(self.two_sessions()), filter_expr="")
        self.assertEqual(len(rec.convs), 2)

    def test_protocol_filter(self):
        pkts = http_like_session() + [udp_pkt(100, C, 5000, S, 53, b"query")]
        rec, _ = self.run_pcap(make_pcap(pkts), filter_expr="udp")
        self.assertEqual(len(rec.convs), 0)
        self.assertEqual([d[1] for d in rec.datagrams], [b"query"])
        rec, _ = self.run_pcap(make_pcap(pkts), filter_expr="tcp")
        self.assertEqual(len(rec.convs), 1)
        self.assertEqual(rec.datagrams, [])

    def test_one_directional_filter_keeps_only_that_direction(self):
        rec, _ = self.run_pcap(make_pcap(http_like_session()), filter_expr="src port 80")
        self.assertEqual(len(rec.convs), 1)
        self.assertEqual(rec.convs[0].server.data, b"HELLO WORLD")
        self.assertEqual(rec.convs[0].client.data, b"")

    def test_packet_filter_callable_receives_protocol_and_flow_id(self):
        seen = []

        def keep_only_80(proto, flow):
            seen.append((proto, flow))
            return 80 in (flow[1], flow[3])

        rec, proc = self.run_pcap(make_pcap(self.two_sessions()), packet_filter=keep_only_80)
        self.assertEqual(len(rec.convs), 1)
        self.assertTrue(all(proto == TCP for proto, _ in seen))
        self.assertTrue(all(isinstance(flow[0], str) and isinstance(flow[1], int) for _, flow in seen))
        self.assertGreater(proc.stats["filtered"], 0)

    def test_packet_filter_and_filter_expr_are_combined_with_and(self):
        rec, _ = self.run_pcap(
            make_pcap(self.two_sessions()),
            filter_expr="tcp",
            packet_filter=lambda proto, flow: flow[3] == 8080 or flow[1] == 8080,
        )
        self.assertEqual(len(rec.convs), 1)
        rec, _ = self.run_pcap(
            make_pcap(self.two_sessions()),
            filter_expr="port 80",
            packet_filter=lambda proto, flow: flow[3] == 8080 or flow[1] == 8080,
        )
        self.assertEqual(len(rec.convs), 0)

    def test_packet_filter_exception_is_not_silently_ignored(self):
        def broken(proto, flow):
            raise OSError("not a read error")

        with self.assertRaises(P.AnalyzerError):
            self.run_pcap(make_pcap(http_like_session()), packet_filter=broken)

    def test_invalid_filter_expr_fails_at_construction(self):
        with self.assertRaises(P.FilterSyntaxError):
            P.PcapStreamProcessor(filter_expr="vlan 5")

    def test_filter_is_applied_after_fragment_reassembly(self):
        """2 つ目以降のフラグメントにはポートがないので、再構成の後で判定される。"""
        l4 = udp(7000, 7001, b"Q" * 40)
        first, second = l4[:24], l4[24:]
        frags = [
            (ms(0), ip4(C, S, 17, first, ident=5, frag_field=0x2000)),
            (ms(1), ip4(C, S, 17, second, ident=5, frag_field=3)),
        ]
        rec, proc = self.run_pcap(make_pcap(frags), filter_expr="udp port 7001")
        self.assertEqual([d[1] for d in rec.datagrams], [b"Q" * 40])
        self.assertEqual(proc.stats["frag_reassembled"], 1)
        rec, proc = self.run_pcap(make_pcap(frags), filter_expr="udp port 9999")
        self.assertEqual(rec.datagrams, [])
        self.assertEqual(proc.stats["filtered"], 1)

    def test_ipv6_filtering(self):
        wrap = lambda ip: (b"\0" * 12 + b"\x86\xdd" + ip)  # noqa: E731
        pkts = [
            (ms(0), ip6("2001:db8::1", "2001:db8::2", 17, udp(1000, 53, b"a"))),
            (ms(1), ip6("2001:db8::1", "2001:db8::3", 17, udp(1000, 54, b"b"))),
        ]
        rec, _ = self.run_pcap(make_pcap(pkts, wrap=wrap), filter_expr="ip6 and host 2001:db8::3")
        self.assertEqual([d[1] for d in rec.datagrams], [b"b"])

    def test_tiny_l4_payload_is_not_filtered_out_or_crashing(self):
        _, proc = self.run_pcap(make_pcap([(ms(0), ip4(C, S, 6, b"\x01\x02"))]), filter_expr="port 80")
        self.assertEqual(proc.stats["filtered"], 0)

    def test_filtered_packets_do_not_create_state(self):
        pkts = [tcp_pkt(i, C, 1000 + i, S, 80, 1, 0, SYN) for i in range(50)]
        rec, proc = self.run_pcap(make_pcap(pkts), filter_expr="port 443")
        self.assertEqual(proc.stats["filtered"], 50)
        self.assertEqual(len(proc._conversations), 0)


@unittest.skipUnless(shutil.which("tcpdump"), "tcpdump が見つからないためスキップ")
class TestAgainstTcpdump(PcapTestCase):
    """ランダムなパケット列について、tcpdump の判定件数と自前の判定件数を突き合わせる。"""

    EXPRESSIONS = [
        "tcp", "udp", "port 80", "src port 80", "dst port 53", "tcp port 80", "udp port 53",
        "portrange 1000-2000", "host 10.0.0.1", "src host 10.0.0.2", "dst host 192.168.1.9",
        "net 10.0.0.0/8", "src net 192.168.0.0/16", "not port 80", "port 80 or 443",
        "tcp and (port 80 or port 443)", "host 10.0.0.1 and not port 80", "ip", "ip6",
        "net 2001:db8::/32", "host 2001:db8::1",
    ]

    def test_counts_match_tcpdump(self):
        rnd = random.Random(2024)
        v4 = ["10.0.0.1", "10.0.0.2", "192.168.1.9", "172.16.5.5"]
        v6 = ["2001:db8::1", "2001:db8::2", "2001:db9::1"]
        ports = [53, 80, 443, 1500, 5000, 1999, 2001]
        packets, meta = [], []
        for i in range(400):
            use_v6 = rnd.random() < 0.2
            src, dst = rnd.sample(v6 if use_v6 else v4, 2)
            sport, dport = rnd.choice(ports), rnd.choice(ports)
            proto = rnd.choice([TCP, UDP])
            if proto == TCP:
                l4 = udp(sport, dport, b"x" * 8)  # ポート位置が同じなので TCP ヘッダの代わりに使う
                l4 = l4[:4] + b"\0" * 8 + b"\x50\x10" + b"\0" * 6
            else:
                l4 = udp(sport, dport, b"x" * 8)
            if use_v6:
                packets.append((ms(i), ip6(src, dst, proto, l4)))
            else:
                packets.append((ms(i), ip4(src, dst, proto, l4)))
            meta.append((proto, src, sport, dst, dport))
        wrap = lambda ip: (b"\0" * 12 + (b"\x86\xdd" if ip[0] >> 4 == 6 else b"\x08\x00") + ip)  # noqa: E731
        path = self.write_pcap(make_pcap(packets, wrap=wrap))
        for expression in self.EXPRESSIONS:
            with self.subTest(expression=expression):
                result = subprocess.run(
                    ["tcpdump", "-n", "-r", path, expression],
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = sum(1 for line in result.stdout.splitlines() if line.strip())
                predicate = P.compile_filter(expression)
                actual = sum(predicate(p, raw(s), sp, raw(d), dp) for p, s, sp, d, dp in meta)
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
