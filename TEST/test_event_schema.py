"""Section 6 checks: one normalized, JSON-compatible output structure."""

import json
import unittest

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP

from parsers import COMMON_EVENT_FIELDS, parse_packet, validate_event


class NormalizedEventTests(unittest.TestCase):
    def events(self):
        samples = [
            (
                "tcp-handshake",
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=40000, dport=80, flags="S"),
            ),
            (
                "http",
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=40000, dport=40100)
                / Raw(load=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            ),
            (
                "dns",
                IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=40000, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="example.test", qtype="A")),
            ),
            (
                "smtp",
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=40000, dport=25)
                / Raw(load=b"EHLO mail.example.test\r\n"),
            ),
            (
                "unknown-application",
                IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=40000, dport=40001)
                / Raw(load=b"unstructured-payload"),
            ),
            ("unsupported-network", Raw(load=b"\x01\x02\x03")),
            (
                "truncated-ipv4-payload",
                IP(src="10.0.0.1", dst="10.0.0.2", proto=17, len=100) / Raw(load=b"short"),
            ),
        ]
        for packet_id, (name, packet) in enumerate(samples, start=1):
            yield name, parse_packet(packet, packet_id)

    def by_protocol(self, application_protocol):
        for name, event in self.events():
            if event["application_protocol"] == application_protocol:
                return event
        self.fail(f"no sample event for {application_protocol}")

    def test_every_event_matches_the_schema(self):
        for name, event in self.events():
            with self.subTest(sample=name):
                self.assertEqual(validate_event(event), [])

    def test_every_event_has_the_common_fields(self):
        for name, event in self.events():
            with self.subTest(sample=name):
                for field in COMMON_EVENT_FIELDS:
                    self.assertIn(field, event)

    def test_every_event_is_json_compatible(self):
        for name, event in self.events():
            with self.subTest(sample=name):
                self.assertEqual(json.loads(json.dumps(event)), event)

    def test_http_event_carries_documented_fields(self):
        event = self.by_protocol("HTTP")
        self.assertTrue(
            {
                "http_message_type",
                "http_method",
                "http_target",
                "http_version",
                "headers",
                "body",
            }.issubset(event)
        )

    def test_dns_event_carries_documented_fields(self):
        event = self.by_protocol("DNS")
        self.assertTrue(
            {
                "dns_transaction_id",
                "dns_is_response",
                "dns_questions",
                "dns_answers",
            }.issubset(event)
        )

    def test_smtp_event_carries_documented_fields(self):
        event = self.by_protocol("SMTP")
        self.assertTrue(
            {"smtp_message_type", "smtp_command", "smtp_argument"}.issubset(event)
        )

    def test_validation_reports_missing_common_fields(self):
        problems = validate_event({"packet_id": 1})
        self.assertTrue(any("missing common field" in problem for problem in problems))

    def test_validation_reports_invalid_values(self):
        event = dict(self.by_protocol("HTTP"))
        event["application_protocol"] = "TELNET"
        event["src_port"] = "80"
        problems = validate_event(event)
        self.assertTrue(any("application_protocol" in problem for problem in problems))
        self.assertTrue(any("src_port" in problem for problem in problems))

    def test_validation_rejects_non_json_values(self):
        event = dict(self.by_protocol("HTTP"))
        event["headers"] = {"raw": b"\x00\x01"}
        problems = validate_event(event)
        self.assertTrue(any("JSON-compatible" in problem for problem in problems))

    def test_validation_reports_undocumented_fields(self):
        event = dict(self.by_protocol("HTTP"))
        event["scapy_packet"] = "Raw"
        problems = validate_event(event)
        self.assertTrue(
            any("undocumented fields" in problem for problem in problems), problems
        )


if __name__ == "__main__":
    unittest.main()
