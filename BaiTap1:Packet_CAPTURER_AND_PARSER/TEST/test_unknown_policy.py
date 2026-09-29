"""Section 5 checks: packets are marked UNKNOWN or skipped by configuration."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scapy.all import IP, Raw, TCP, UDP, wrpcap

import main
from parsers import validate_event


UNKNOWN_PACKET = (
    IP(src="10.0.0.1", dst="10.0.0.2")
    / UDP(sport=40000, dport=40001)
    / Raw(load=bytes(range(16)))
)
HTTP_PACKET = (
    IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=40000, dport=40100)
    / Raw(load=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
)


class UnknownPolicyTests(unittest.TestCase):
    def setUp(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.pcap_file = str(Path(tempdir.name) / "mixed.pcap")
        self.output_file = str(Path(tempdir.name) / "events.jsonl")
        wrpcap(self.pcap_file, [UNKNOWN_PACKET, HTTP_PACKET])

    def read_events(self):
        text = Path(self.output_file).read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def run_capture(self, *extra_arguments):
        with redirect_stdout(io.StringIO()):
            return main.main(
                [
                    "--pcap",
                    self.pcap_file,
                    "--output",
                    self.output_file,
                    *extra_arguments,
                ]
            )

    def test_unknown_packets_are_marked_by_default(self):
        self.assertEqual(self.run_capture(), 0)
        events = self.read_events()
        self.assertEqual(
            [event["application_protocol"] for event in events], ["UNKNOWN", "HTTP"]
        )
        self.assertEqual([event["packet_id"] for event in events], [1, 2])
        self.assertEqual([validate_event(event) for event in events], [[], []])

    def test_skip_policy_drops_unknown_events(self):
        self.assertEqual(self.run_capture("--unknown-policy", "skip"), 0)
        events = self.read_events()
        self.assertEqual([event["application_protocol"] for event in events], ["HTTP"])
        self.assertEqual([event["packet_id"] for event in events], [2])

    def test_skip_policy_applies_to_standard_output(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.main(["--pcap", self.pcap_file, "--unknown-policy", "skip"])
        self.assertEqual(result, 0)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([event["application_protocol"] for event in events], ["HTTP"])

    def test_invalid_policy_is_rejected_before_capture(self):
        with patch("main.sniff") as sniff, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main.main(["--interface", "test0", "--unknown-policy", "drop"])
        self.assertEqual(error.exception.code, 2)
        sniff.assert_not_called()

    def test_handler_rejects_invalid_policy(self):
        with self.assertRaises(ValueError):
            main.make_packet_handler(io.StringIO(), unknown_policy="drop")

    def test_marked_unknown_event_keeps_diagnostics(self):
        self.assertEqual(self.run_capture(), 0)
        unknown_event = self.read_events()[0]
        self.assertEqual(unknown_event["application_protocol"], "UNKNOWN")
        self.assertEqual(unknown_event["parse_status"], "OK")
        self.assertEqual(unknown_event["payload_length"], 16)


if __name__ == "__main__":
    unittest.main()
