"""Section 4 checks: protocol parsing must not depend on standard ports.

Every packet is serialized and re-parsed before detection, and the test
asserts that Scapy did not decode an application layer from the port number.
Only the payload-based detector can identify the protocol in that situation.
"""

import unittest

from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP, UDP

from parsers import parse_packet


class NonStandardPortTests(unittest.TestCase):
    def parse(self, packet, packet_id=1):
        serialized = IP(bytes(packet))
        self.assertFalse(
            serialized.haslayer(DNS),
            "Scapy must not decode a DNS layer on a non-standard port",
        )
        return parse_packet(serialized, packet_id)

    def tcp(self, payload, sport, dport):
        return (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=sport, dport=dport)
            / Raw(load=payload)
        )

    def test_http_request_on_non_standard_port(self):
        event = self.parse(
            self.tcp(
                b"PUT /upload HTTP/1.0\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n",
                sport=40000,
                dport=18080,
            )
        )
        self.assertEqual(event["application_protocol"], "HTTP")
        self.assertEqual(event["http_method"], "PUT")
        self.assertEqual(event["http_target"], "/upload")
        self.assertEqual(event["http_version"], "HTTP/1.0")

    def test_http_response_on_non_standard_port(self):
        event = self.parse(
            self.tcp(
                b"HTTP/1.0 404 Not Found\r\nServer: example.test\r\n\r\n",
                sport=19090,
                dport=40000,
            )
        )
        self.assertEqual(event["application_protocol"], "HTTP")
        self.assertEqual(event["http_message_type"], "response")
        self.assertEqual(event["status_code"], 404)
        self.assertEqual(event["reason_phrase"], "Not Found")

    def test_dns_query_on_non_standard_port(self):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=40000, dport=53000)
            / DNS(rd=1, qd=DNSQR(qname="example.test", qtype="A"))
        )
        event = self.parse(packet)
        self.assertEqual(event["application_protocol"], "DNS")
        self.assertFalse(event["dns_is_response"])
        self.assertEqual(
            event["dns_questions"], [{"name": "example.test", "type": "A"}]
        )

    def test_dns_response_on_non_standard_port(self):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=53111, dport=40000)
            / DNS(
                id=33,
                qr=1,
                qd=DNSQR(qname="example.test", qtype="A"),
                an=DNSRR(rrname="example.test", type="A", ttl=30, rdata="192.0.2.99"),
            )
        )
        event = self.parse(packet)
        self.assertEqual(event["application_protocol"], "DNS")
        self.assertTrue(event["dns_is_response"])
        self.assertEqual(event["dns_transaction_id"], 33)
        self.assertEqual(
            event["dns_answers"],
            [
                {
                    "name": "example.test",
                    "type": "A",
                    "ttl": 30,
                    "data": "192.0.2.99",
                }
            ],
        )

    def test_dns_over_tcp_with_length_prefix_on_non_standard_port(self):
        message = bytes(DNS(id=9, rd=1, qd=DNSQR(qname="tcp.example.test", qtype="AAAA")))
        framed = len(message).to_bytes(2, "big") + message
        event = self.parse(self.tcp(framed, sport=40000, dport=53530))
        self.assertEqual(event["application_protocol"], "DNS")
        self.assertEqual(event["dns_transaction_id"], 9)
        self.assertEqual(
            event["dns_questions"], [{"name": "tcp.example.test", "type": "AAAA"}]
        )

    def test_smtp_command_on_non_standard_port(self):
        event = self.parse(self.tcp(b"RCPT TO:<user@example.test>\r\n", 40000, 2526))
        self.assertEqual(event["application_protocol"], "SMTP")
        self.assertEqual(event["smtp_message_type"], "command")
        self.assertEqual(event["smtp_command"], "RCPT TO")
        self.assertEqual(event["smtp_argument"], "<user@example.test>")

    def test_smtp_response_on_non_standard_port(self):
        event = self.parse(
            self.tcp(b"220 mail.example.test ESMTP ready\r\n", 2526, 40000)
        )
        self.assertEqual(event["application_protocol"], "SMTP")
        self.assertEqual(event["smtp_message_type"], "response")
        self.assertEqual(event["smtp_status_code"], 220)
        self.assertEqual(event["smtp_text"], "mail.example.test ESMTP ready")

    def test_unstructured_payload_on_high_port_stays_unknown(self):
        payload = bytes(range(16))
        event = self.parse(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=40000, dport=40100)
            / Raw(load=payload)
        )
        self.assertEqual(event["application_protocol"], "UNKNOWN")
        self.assertEqual(event["parse_status"], "OK")


if __name__ == "__main__":
    unittest.main()
