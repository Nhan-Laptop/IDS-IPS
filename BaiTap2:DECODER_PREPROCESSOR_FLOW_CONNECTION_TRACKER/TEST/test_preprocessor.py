"""Required validation and normalization cases."""

import unittest

from preprocessor import preprocess_event
from TEST.common import sample_event


class PreprocessorTests(unittest.TestCase):
    def test_T14_malformed_and_unsupported(self):
        import json
        bad_inputs = [None, [], {}, sample_event(src_ip="not-an-ip"),
                      sample_event(dst_port=65536), sample_event(src_port=True),
                      sample_event(src_port="9" * 6000), sample_event(timestamp="bad time"),
                      sample_event(timestamp=float("nan")), sample_event(transport_protocol="ICMP"),
                      sample_event(packet_length=-1), sample_event(extra=object())]
        for event in bad_inputs:
            with self.subTest(event_type=type(event).__name__):
                result = preprocess_event(event)
                self.assertEqual(result["preprocess_status"], "invalid")
                self.assertEqual(result["processing_action"], "mark")
                self.assertFalse(result["trackable"])
                self.assertTrue(result["reason"])
                json.dumps(result, allow_nan=False)
                self.assertEqual(preprocess_event(event, "skip")["processing_action"], "skip")
        good = preprocess_event(sample_event())
        self.assertEqual(good["preprocess_status"], "valid")
        self.assertTrue(good["trackable"])
        unknown = preprocess_event(sample_event(application_protocol="TLS"))
        self.assertEqual(unknown["application_protocol"], "UNKNOWN")
        self.assertEqual(unknown["preprocess_status"], "partial")
        self.assertTrue(unknown["trackable"])

    def test_T06_missing_optional_fields(self):
        event = {name: value for name, value in sample_event().items() if name in (
            "src_ip", "dst_ip", "src_port", "dst_port", "timestamp", "transport_protocol", "packet_length")}
        result = preprocess_event(event)
        self.assertTrue(result["trackable"])
        self.assertEqual(result["preprocess_status"], "partial")
        for field in ("packet_id", "body", "http_target", "tcp_sequence", "payload_length"):
            self.assertIsNone(result[field], field)
        for field in ("tcp_flags", "dns_questions", "dns_answers"):
            self.assertEqual(result[field], [], field)
        self.assertEqual(result["headers"], {})
        self.assertEqual(result["application_protocol"], "UNKNOWN")
        explicit_null = dict(event, tcp_flags=None, dns_questions=None, dns_answers=None, headers=None)
        self.assertEqual(preprocess_event(explicit_null)["dns_questions"], [])

    def test_T05_normalization(self):
        event = sample_event(
            transport_protocol=" tcp ", application_protocol=" http ", network_protocol=" ipv4 ",
            src_ip=" 10.0.0.1 ", src_port="40000", timestamp="2024-01-01T07:00:00+07:00",
            headers={" HOST ": " EXAMPLE.TEST ", "X-Token": "KeepCase"},
            dns_questions=[{"name": " EXAMPLE.COM. ", "type": "A"}],
            dns_answers=[{"name": "WWW.Example.COM.", "type": "CNAME", "data": "EXAMPLE.COM."}],
            http_target="/KeepCase/%2f?q=A+B", tcp_flags=["ack", "syn", "ack"])
        result = preprocess_event(event)
        self.assertEqual(result["preprocess_status"], "valid")
        self.assertEqual(result["transport_protocol"], "TCP")
        self.assertEqual(result["application_protocol"], "HTTP")
        self.assertEqual(result["network_protocol"], "IPv4")
        self.assertEqual(result["timestamp"], "2024-01-01T00:00:00+00:00")
        self.assertEqual(result["headers"], {"host": "example.test", "x-token": "KeepCase"})
        self.assertEqual(result["dns_questions"][0]["name"], "example.com")
        self.assertEqual(result["dns_answers"][0]["data"], "example.com")
        self.assertEqual(result["normalized_http_target"], "/KeepCase/%2F?q=A+B")
        self.assertEqual(result["http_target"], event["http_target"])
        self.assertEqual(result["tcp_flags"], ["SYN", "ACK"])
        self.assertEqual(event["dns_questions"][0]["name"], " EXAMPLE.COM. ")
        self.assertEqual(preprocess_event(result), result)
        ipv6 = preprocess_event(sample_event(src_ip="2001:0DB8:0000::1"))
        self.assertEqual(ipv6["src_ip"], "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
