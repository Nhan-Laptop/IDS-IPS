"""Section 8 checks: parse results are written as a JSON Lines log."""

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


def mixed_packets():
    """Unknown, HTTP and DNS packets, in that capture order."""
    return [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=40000, dport=40001)
        / Raw(load=bytes(range(16))),
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=40100)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=53),
    ]


class JsonLinesLogTests(unittest.TestCase):
    def setUp(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.directory = Path(tempdir.name)
        self.pcap_file = str(self.directory / "packets.pcap")
        self.log_file = str(self.directory / "events.jsonl")
        wrpcap(self.pcap_file, mixed_packets())

    def run_capture(self, *arguments):
        with redirect_stdout(io.StringIO()):
            return main.main(
                ["--pcap", self.pcap_file, "--output", self.log_file, *arguments]
            )

    def read_events(self):
        text = Path(self.log_file).read_text(encoding="utf-8")
        return text, [json.loads(line) for line in text.splitlines()]

    def test_log_has_one_json_object_per_line(self):
        self.assertEqual(self.run_capture(), 0)
        text, events = self.read_events()
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(len(events), 3)
        self.assertEqual([event["packet_id"] for event in events], [1, 2, 3])
        self.assertEqual([validate_event(event) for event in events], [[], [], []])

    def test_log_keeps_capture_order_and_protocols(self):
        self.run_capture()
        _, events = self.read_events()
        self.assertEqual(
            [event["application_protocol"] for event in events],
            ["UNKNOWN", "HTTP", "DNS"],
        )

    def test_skip_policy_writes_one_line_per_written_event(self):
        self.run_capture("--unknown-policy", "skip")
        _, events = self.read_events()
        self.assertEqual(
            [event["application_protocol"] for event in events], ["HTTP", "DNS"]
        )
        self.assertEqual([event["packet_id"] for event in events], [2, 3])

    def test_log_records_capture_failure(self):
        with patch("main.sniff", side_effect=PermissionError("no permission")):
            with redirect_stderr(io.StringIO()):
                result = main.main(["--interface", "test0", "--output", self.log_file])
        self.assertEqual(result, 1)
        _, events = self.read_events()
        self.assertEqual(len(events), 1)
        self.assertIn("capture failed", events[0]["error"])
        self.assertEqual(validate_event(events[0]), [])

    def test_log_records_truncated_pcap_notice(self):
        path = self.directory / "cut.pcap"
        wrpcap(str(path), mixed_packets())
        path.write_bytes(path.read_bytes()[:-10])
        with redirect_stdout(io.StringIO()):
            result = main.main(["--pcap", str(path), "--output", self.log_file])
        self.assertEqual(result, 0)
        _, events = self.read_events()
        self.assertTrue(
            any("truncated PCAP" in event.get("error", "") for event in events), events
        )

    def test_writer_counts_processed_and_written_events(self):
        stream = io.StringIO()
        writer = main.PacketEventWriter(stream, unknown_policy="skip")
        writer(mixed_packets()[0])
        writer(mixed_packets()[1])
        self.assertEqual(writer.packet_id, 2)
        self.assertEqual(writer.written, 1)
        self.assertEqual(len(stream.getvalue().splitlines()), 1)

    def test_standard_output_is_also_json_lines(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.main(["--pcap", self.pcap_file])
        self.assertEqual(result, 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 3)
        for line in lines:
            self.assertIn("packet_id", json.loads(line))


if __name__ == "__main__":
    unittest.main()
