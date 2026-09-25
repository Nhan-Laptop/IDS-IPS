"""Section 7 checks: bad input never stops the capture pipeline."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap
from scapy.error import Scapy_Exception

import main
from parsers import error_event, parse_packet, validate_event


class ErrorHandlingTests(unittest.TestCase):
    def test_malformed_ipv4_header_does_not_crash(self):
        raw = bytearray(
            bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2))
        )
        raw[0] = 0x43  # version 4 with a 12-byte header, which is not allowed
        event = parse_packet(IP(bytes(raw)), 1)
        self.assertEqual(event["parse_status"], "MALFORMED")
        self.assertIn("IPv4 header length", event["error"])
        self.assertEqual(validate_event(event), [])

    def test_unsupported_transport_protocol_does_not_crash(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2", proto=1) / Raw(load=b"\x08\x00")
        event = parse_packet(packet, 1)
        self.assertEqual(event["parse_status"], "UNSUPPORTED")
        self.assertEqual(event["transport_protocol"], "UNKNOWN")
        self.assertEqual(validate_event(event), [])

    def test_missing_ipv4_header_does_not_crash(self):
        event = parse_packet(Ether() / Raw(load=b"\x00" * 20), 1)
        self.assertEqual(event["parse_status"], "UNSUPPORTED")
        self.assertEqual(event["network_protocol"], "UNKNOWN")
        self.assertEqual(validate_event(event), [])

    def test_empty_payload_does_not_crash(self):
        empty_dns = parse_packet(IP(bytes(IP() / UDP(sport=40000, dport=53))), 1)
        self.assertEqual(empty_dns["application_protocol"], "DNS")
        self.assertEqual(empty_dns["parse_status"], "MALFORMED")
        self.assertIn("empty DNS payload", empty_dns["error"])

        empty_tcp = parse_packet(
            IP(bytes(IP() / TCP(sport=40000, dport=80, flags="S"))), 2
        )
        self.assertEqual(empty_tcp["application_protocol"], "UNKNOWN")
        self.assertEqual(empty_tcp["parse_status"], "OK")
        self.assertEqual(validate_event(empty_tcp), [])

    def test_truncated_transport_header_does_not_crash(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2", proto=6) / Raw(load=b"\x00\x01")
        event = parse_packet(packet, 1)
        self.assertEqual(event["parse_status"], "INCOMPLETE")
        self.assertIn("truncated TCP header", event["error"])
        self.assertEqual(validate_event(event), [])

    def test_undecodable_http_body_does_not_crash(self):
        payload = (
            b"POST /submit HTTP/1.1\r\nHost: example.test\r\n\r\n" + bytes([0xFF, 0xFE, 0x80])
        )
        event = parse_packet(IP() / TCP(sport=40000, dport=80) / Raw(load=payload), 1)
        self.assertEqual(event["parse_status"], "OK")
        self.assertIn("\ufffd", event["body"])
        self.assertEqual(validate_event(event), [])

    def test_undecodable_dns_payload_does_not_crash(self):
        packet = IP() / UDP(sport=40000, dport=53) / Raw(load=b"\xff\xfe\xfd")
        event = parse_packet(IP(bytes(packet)), 1)
        self.assertEqual(event["application_protocol"], "DNS")
        self.assertEqual(event["parse_status"], "MALFORMED")
        self.assertIn("DNS decode failed", event["error"])
        self.assertEqual(validate_event(event), [])

    def test_parser_failure_is_contained(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2)
        with patch("main.parse_packet", side_effect=RuntimeError("boom")):
            event = main._parse_safely(packet, 7)
        self.assertEqual(event["packet_id"], 7)
        self.assertEqual(event["parse_status"], "MALFORMED")
        self.assertIn("parser failure contained", event["error"])
        self.assertEqual(validate_event(event), [])

    def test_error_event_is_schema_valid(self):
        event = error_event(3, "truncated PCAP packet", status="INCOMPLETE")
        self.assertEqual(event["parse_status"], "INCOMPLETE")
        self.assertEqual(event["packet_id"], 3)
        self.assertEqual(validate_event(event), [])

    def test_truncated_file_still_processes_readable_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trailing-record.pcap"
            packets = [
                IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000 + index, dport=53)
                for index in range(3)
            ]
            wrpcap(str(path), packets)
            # keep the global header, the first record and only 8 bytes of the next
            path.write_bytes(path.read_bytes()[: 24 + 16 + len(bytes(packets[0])) + 8])
            output = io.StringIO()
            with redirect_stdout(output):
                result = main.main(["--pcap", str(path)])
            self.assertEqual(result, 0)
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(validate_event(events[0]), [])

    def test_truncated_record_data_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cut-record.pcap"
            packets = [
                IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=1000 + index, dport=53)
                / Raw(load=b"A" * 20)
                for index in range(2)
            ]
            wrpcap(str(path), packets)
            path.write_bytes(path.read_bytes()[:-10])
            output = io.StringIO()
            with redirect_stdout(output):
                result = main.main(["--pcap", str(path)])
            self.assertEqual(result, 0)
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertTrue(
                any("truncated PCAP packet" in event.get("error", "") for event in events),
                events,
            )
            self.assertTrue(all(validate_event(event) == [] for event in events))

    def test_unreadable_record_is_reported_without_stopping(self):
        class BrokenReader:
            snaplen = 65535

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def __next__(self):
                raise Scapy_Exception("record could not be decoded")

        output = io.StringIO()
        with patch("main.PcapReader", return_value=BrokenReader()):
            with redirect_stdout(output):
                result = main.main(["--pcap", "broken.pcap"])
        self.assertEqual(result, 0)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["parse_status"], "INCOMPLETE")
        self.assertIn("unreadable PCAP record", events[0]["error"])

    def test_capture_failure_returns_error_code_instead_of_crashing(self):
        errors = [
            PermissionError("capture permission denied"),
            OSError("interface not found"),
            Scapy_Exception("capture setup failed"),
        ]
        for error in errors:
            with self.subTest(error=error):
                with patch("main.sniff", side_effect=error), redirect_stderr(io.StringIO()):
                    self.assertEqual(main.main(["--interface", "test0"]), 1)

    def test_interrupt_returns_shell_convention(self):
        with patch("main.sniff", side_effect=KeyboardInterrupt), redirect_stderr(io.StringIO()):
            self.assertEqual(main.main(["--interface", "test0"]), 130)


if __name__ == "__main__":
    unittest.main()
