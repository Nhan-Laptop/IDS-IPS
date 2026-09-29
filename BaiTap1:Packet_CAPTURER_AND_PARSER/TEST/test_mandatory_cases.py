"""Section 9 mandatory test cases, executed through the capture CLI.

Each test case writes a PCAP built by ``mandatory_cases`` and runs the real
command line entry point on it, so the assertions cover the complete path:
PCAP import, shared parsing pipeline, normalized event and JSON Lines log.
"""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scapy.all import wrpcap

import main
from parsers import validate_event

TEST_DIR = Path(__file__).resolve().parent


def _load_cases():
    """Load the sibling packet builder module without relying on sys.path."""
    spec = importlib.util.spec_from_file_location(
        "mandatory_cases", TEST_DIR / "mandatory_cases.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CASES = _load_cases()


class MandatoryCaseTests(unittest.TestCase):
    def run_case(self, name):
        """Run one mandatory case through the CLI and return its events."""
        packets = dict(CASES.cases())[name]()
        with tempfile.TemporaryDirectory() as directory:
            pcap_file = Path(directory) / f"{name}.pcap"
            log_file = Path(directory) / f"{name}.jsonl"
            wrpcap(str(pcap_file), packets)
            with redirect_stdout(io.StringIO()):
                result = main.main(["--pcap", str(pcap_file), "--output", str(log_file)])
            self.assertEqual(result, 0)
            text = log_file.read_text(encoding="utf-8")
            events = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(len(events), len(packets))
        for event in events:
            self.assertEqual(validate_event(event), [])
        return events

    def test_tcp_handshake(self):
        events = self.run_case("tcp_handshake")
        self.assertEqual(
            [event["tcp_flags"] for event in events],
            [["SYN"], ["SYN", "ACK"], ["ACK"]],
        )
        self.assertEqual([event["transport_protocol"] for event in events], ["TCP"] * 3)

    def test_tcp_data(self):
        events = self.run_case("tcp_data")
        event = events[0]
        self.assertEqual(event["transport_protocol"], "TCP")
        self.assertEqual(event["payload_length"], len(b"hello tcp payload"))
        self.assertEqual(event["src_port"], 40000)
        self.assertEqual(event["dst_port"], 9000)

    def test_udp(self):
        events = self.run_case("udp")
        event = events[0]
        self.assertEqual(event["transport_protocol"], "UDP")
        self.assertEqual(event["payload_length"], len(b"hello udp payload"))
        self.assertEqual(event["dst_port"], 9001)

    def test_http_get(self):
        events = self.run_case("http_get")
        event = events[0]
        self.assertEqual(event["application_protocol"], "HTTP")
        self.assertEqual(event["http_message_type"], "request")
        self.assertEqual(event["http_method"], "GET")
        self.assertEqual(event["http_target"], "/index.html")
        self.assertEqual(event["http_version"], "HTTP/1.1")
        self.assertEqual(event["headers"]["host"], "example.test")

    def test_http_post(self):
        events = self.run_case("http_post")
        event = events[0]
        self.assertEqual(event["http_method"], "POST")
        self.assertEqual(event["http_target"], "/login")
        self.assertEqual(event["body"], "username=alice&password=secret")
        self.assertEqual(event["headers"]["content-length"], "30")

    def test_http_response(self):
        events = self.run_case("http_response")
        event = events[0]
        self.assertEqual(event["http_message_type"], "response")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["reason_phrase"], "OK")
        self.assertEqual(event["headers"]["server"], "ids-test")
        self.assertEqual(event["http_version"], "HTTP/1.1")

    def test_dns_query(self):
        events = self.run_case("dns_query")
        event = events[0]
        self.assertEqual(event["application_protocol"], "DNS")
        self.assertFalse(event["dns_is_response"])
        self.assertEqual(
            event["dns_questions"], [{"name": "example.com", "type": "A"}]
        )

    def test_dns_response(self):
        events = self.run_case("dns_response")
        event = events[0]
        self.assertTrue(event["dns_is_response"])
        self.assertEqual(
            event["dns_answers"],
            [
                {
                    "name": "example.com",
                    "type": "A",
                    "ttl": 300,
                    "data": "93.184.216.34",
                }
            ],
        )

    def test_smtp_command(self):
        events = self.run_case("smtp_command")
        self.assertEqual(
            [event["application_protocol"] for event in events], ["SMTP"] * 3
        )
        self.assertEqual(
            [event["smtp_command"] for event in events],
            ["EHLO", "MAIL FROM", "RCPT TO"],
        )
        self.assertEqual(events[0]["smtp_argument"], "mail.example.test")
        self.assertEqual(events[1]["smtp_argument"], "<alice@example.test>")
        self.assertEqual(events[2]["smtp_argument"], "<bob@example.test>")

    def test_smtp_response(self):
        events = self.run_case("smtp_response")
        event = events[0]
        self.assertEqual(event["application_protocol"], "SMTP")
        self.assertEqual(event["smtp_message_type"], "response")
        self.assertEqual(event["smtp_status_code"], 250)
        self.assertEqual(event["smtp_text"], "2.1.0 Ok")

    def test_unknown_protocol_does_not_crash(self):
        events = self.run_case("unknown_protocol")
        event = events[0]
        self.assertEqual(event["application_protocol"], "UNKNOWN")
        self.assertEqual(event["parse_status"], "OK")

    def test_malformed_packet_does_not_crash(self):
        events = self.run_case("malformed_packet")
        event = events[0]
        self.assertEqual(event["parse_status"], "MALFORMED")
        self.assertIn("IPv4 header length", event["error"])


if __name__ == "__main__":
    unittest.main()
