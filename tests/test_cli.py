# SPDX-License-Identifier: MPL-2.0
"""コマンドライン(python -m pcapreasm / pcapreasm.main)のテスト(0.2.0 で追加)。"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import pcapreasm as P  # noqa: E402
from test_pcapreasm import (  # noqa: E402
    ACK, C, PSH, S, http_like_session, make_pcap, tcp_pkt, udp_pkt,
)

def session_at(index):
    """index 番目の(別ポート・別時刻の)HTTP 風セッション。"""
    return [(t + index * 1_000_000_000, data) for t, data in http_like_session(cport=2000 + index)]


ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def write(self, name, data):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = P.main(list(argv))
            except SystemExit as exit_:  # argparse errors
                code = exit_.code
        return code, out.getvalue(), err.getvalue()


class TestOutput(CliTestCase):
    def test_text_summary_of_one_conversation(self):
        path = self.write("a.pcap", make_pcap(http_like_session()))
        code, out, _ = self.run_main(path)
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, out)
        self.assertIn(" TCP ", lines[0])
        self.assertIn("-> ", lines[0])
        self.assertIn("end=fin", lines[0])
        self.assertRegex(lines[0], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z ")

    def test_jsonl_has_one_object_per_line(self):
        path = self.write("a.pcap", make_pcap(http_like_session()))
        code, out, _ = self.run_main(path, "--format", "jsonl")
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["type"], "tcp")
        self.assertGreater(record["client_bytes"], 0)
        self.assertGreater(record["server_bytes"], 0)
        self.assertEqual(record["gaps"], 0)
        self.assertTrue(record["client_certain"])

    def test_udp_flows_only_with_the_option(self):
        pkts = [udp_pkt(0, C, 5000, S, 53, b"abc"), udp_pkt(1, C, 5000, S, 53, b"defg")]
        path = self.write("u.pcap", make_pcap(pkts))
        self.assertEqual(self.run_main(path)[1], "")
        code, out, _ = self.run_main(path, "--udp", "--format", "jsonl")
        self.assertEqual(code, 0)
        record = json.loads(out)
        self.assertEqual((record["type"], record["datagrams"], record["bytes"]), ("udp", 2, 7))

    def test_filter_option_drops_other_traffic(self):
        pkts = [
            tcp_pkt(0, C, 1111, S, 80, 1000, 0, PSH | ACK, b"web"),
            tcp_pkt(1, C, 2222, S, 22, 1000, 0, PSH | ACK, b"ssh"),
        ]
        path = self.write("f.pcap", make_pcap(pkts))
        _, out, _ = self.run_main(path, "-f", "tcp and port 22", "--format", "jsonl")
        records = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([r["server"].endswith(":22") for r in records], [True])

    def test_ipv6_endpoints_are_bracketed(self):
        self.assertEqual(P._endpoint("fe80::1", 80), "[fe80::1]:80")
        self.assertEqual(P._endpoint("10.0.0.1", 80), "10.0.0.1:80")

    def test_times_are_utc_with_milliseconds(self):
        self.assertEqual(P._format_timestamp(0), "1970-01-01T00:00:00.000Z")
        self.assertEqual(P._format_timestamp(1_700_000_000_123_456_789), "2023-11-14T22:13:20.123Z")

    def test_stats_go_to_stderr_not_stdout(self):
        path = self.write("a.pcap", make_pcap(http_like_session()))
        _, out, err = self.run_main(path, "--stats")
        self.assertNotIn("[stats]", out)
        self.assertIn("[stats]", err)
        self.assertIn("'packets'", err)


class TestInputsAndErrors(CliTestCase):
    def test_file_list_and_blank_lines(self):
        first = self.write("a.pcap", make_pcap(http_like_session()))
        second = self.write("b.pcap", make_pcap(session_at(5)))
        lst = self.write("list.txt", ("%s\n\n%s\n" % (first, second)).encode())
        code, out, _ = self.run_main("-l", lst)
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 2)

    def test_no_files_is_a_usage_error(self):
        code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("no PCAP files", err)

    def test_bad_filter_is_a_usage_error(self):
        path = self.write("a.pcap", make_pcap(http_like_session()))
        code, _, err = self.run_main(path, "-f", "tcp and (")
        self.assertEqual(code, 2)
        self.assertIn("invalid filter", err)

    def test_missing_file_exits_1(self):
        code, _, err = self.run_main(os.path.join(self._tmp.name, "nope.pcap"))
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)

    def test_missing_file_list_exits_1(self):
        code, _, err = self.run_main("-l", os.path.join(self._tmp.name, "nope.txt"))
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)

    def test_not_a_pcap_exits_1_and_on_error_skip_continues(self):
        bad = self.write("bad.pcap", b"this is not a pcap file at all, just text")
        good = self.write("good.pcap", make_pcap(http_like_session()))
        code, _, err = self.run_main(bad, good)
        self.assertEqual(code, 1)
        self.assertIn("Error:", err)
        code, out, _ = self.run_main(bad, good, "--on-error", "skip")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)

    def test_version(self):
        code, out, _ = self.run_main("--version")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "pcapreasm " + P.__version__)

    def test_negative_limits_are_rejected(self):
        path = self.write("a.pcap", make_pcap(http_like_session()))
        self.assertEqual(self.run_main(path, "--max-memory-mb", "-1")[0], 2)
        self.assertEqual(self.run_main(path, "--idle-timeout", "-1")[0], 2)


class TestAsModule(CliTestCase):
    def run_module(self, *args, stdin=None):
        env = dict(os.environ, PYTHONPATH=os.path.abspath(ROOT))
        return subprocess.run(
            [sys.executable, "-m", "pcapreasm", *args], input=stdin, capture_output=True, env=env, timeout=60
        )

    def test_python_dash_m(self):
        path = self.write("a.pcap", make_pcap(http_like_session()))
        result = self.run_module(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b" TCP ", result.stdout)

    def test_stdin(self):
        result = self.run_module("-", stdin=make_pcap(http_like_session()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b" TCP ", result.stdout)

    def test_closed_pipe_is_quiet(self):
        pkts = []
        for i in range(2000):
            pkts += session_at(i)
        path = self.write("many.pcap", make_pcap(pkts))
        env = dict(os.environ, PYTHONPATH=os.path.abspath(ROOT))
        proc = subprocess.Popen(
            [sys.executable, "-m", "pcapreasm", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        assert proc.stdout is not None
        proc.stdout.readline()
        proc.stdout.close()
        assert proc.stderr is not None
        stderr = proc.stderr.read()
        proc.stderr.close()
        proc.wait(timeout=60)
        self.assertEqual(proc.returncode, 0, stderr)
        self.assertEqual(stderr, b"")


if __name__ == "__main__":
    unittest.main()
