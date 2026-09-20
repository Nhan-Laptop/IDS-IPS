"""Required protocol and error-handling tests for the packet pipeline."""

import json
import unittest

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

from parsers import parse_packet


class PacketPipelineTests(unittest.TestCase):
    def setUp(self):
        self.packet_id = 0

    def parse(self, packet):
        self.packet_id += 1
        return parse_packet(IP(bytes(packet)), self.packet_id)

    def tcp(self, payload=b"", sport=40000, dport=40001, flags="PA"):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=sport, dport=dport, flags=flags
        )
        return packet / Raw(load=payload) if payload else packet

    def udp(self, payload=b"", sport=40000, dport=40001):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
            sport=sport, dport=dport
        )
        return packet / Raw(load=payload) if payload else packet


    def test_tcp_handshake(self):
        packets = [
            self.tcp(sport=40000, dport=80, flags="S"),
            self.tcp(sport=80, dport=40000, flags="SA"),
            self.tcp(sport=40000, dport=80, flags="A"),
        ]
        events = [self.parse(packet) for packet in packets]
        self.assertEqual([event["tcp_flags"] for event in events], [
            ["SYN"], ["SYN", "ACK"], ["ACK"]
        ])
        self.assertTrue(all(event["parse_status"] == "OK" for event in events))

    def test_tcp_data(self):
        event = self.parse(self.tcp(b"hello", sport=1234, dport=4321))
        self.assertEqual(event["transport_protocol"], "TCP")
        self.assertEqual(event["payload_length"], 5)
        self.assertEqual(event["src_port"], 1234)
        self.assertEqual(event["dst_port"], 4321)

    def test_udp(self):
        event = self.parse(self.udp(b"hello", sport=1234, dport=4321))
        self.assertEqual(event["transport_protocol"], "UDP")
        self.assertEqual(event["payload_length"], 5)
        self.assertEqual(event["parse_status"], "OK")

    def test_http_get_on_non_standard_port(self):
        event = self.parse(self.tcp(
            b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n",
            sport=40000,
            dport=18080,
        ))
        self.assertEqual(event["application_protocol"], "HTTP")
        self.assertEqual(event["http_message_type"], "request")
        self.assertEqual(event["http_method"], "GET")
        self.assertEqual(event["http_target"], "/index.html")
        self.assertEqual(event["headers"]["host"], "example.test")

    def test_http_post_with_body(self):
        event = self.parse(self.tcp(
            b"POST /login HTTP/1.1\r\nContent-Length: 9\r\n\r\nuser=alice",
            dport=80,
        ))
        self.assertEqual(event["http_method"], "POST")
        self.assertEqual(event["body"], "user=alice")
        self.assertEqual(event["headers"]["content-length"], "9")

    def test_http_response(self):
        event = self.parse(self.tcp(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
            sport=80,
            dport=40000,
        ))
        self.assertEqual(event["application_protocol"], "HTTP")
        self.assertEqual(event["http_message_type"], "response")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["reason_phrase"], "OK")

    def test_dns_query(self):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=40000, dport=53000)
            / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        )
        event = self.parse(packet)
        self.assertEqual(event["application_protocol"], "DNS")
        self.assertFalse(event["dns_is_response"])
        self.assertEqual(event["dns_questions"], [{"name": "example.com", "type": "A"}])

    def test_dns_response(self):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=53000, dport=40000)
            / DNS(
                id=7,
                qr=1,
                qd=DNSQR(qname="example.com", qtype="A"),
                an=DNSRR(rrname="example.com", type="A", ttl=60, rdata="192.0.2.10"),
            )
        )
        event = self.parse(packet)
        self.assertTrue(event["dns_is_response"])
        self.assertEqual(event["dns_answers"][0]["type"], "A")
        self.assertEqual(event["dns_answers"][0]["data"], "192.0.2.10")

    def test_smtp_commands(self):
        for command, argument in (("HELO", "mail.example"), ("EHLO", "mail.example"),
                                  ("MAIL FROM", "<a@example.com>"), ("RCPT TO", "<b@example.com>")):
            with self.subTest(command=command):
                event = self.parse(self.tcp(
                    f"{command} {argument}\r\n".encode(), dport=25
                ))
                self.assertEqual(event["application_protocol"], "SMTP")
                self.assertEqual(event["smtp_command"], command)
                self.assertEqual(event["smtp_argument"], argument)

    def test_smtp_response(self):
        event = self.parse(self.tcp(b"250 2.0.0 OK\r\n", sport=25, dport=40000))
        self.assertEqual(event["application_protocol"], "SMTP")
        self.assertEqual(event["smtp_status_code"], 250)
        self.assertEqual(event["smtp_text"], "2.0.0 OK")

    def test_unknown_protocol_does_not_crash(self):
        event = self.parse(self.udp(b"not a supported application", sport=40000, dport=40001))
        self.assertEqual(event["application_protocol"], "UNKNOWN")
        self.assertEqual(event["parse_status"], "OK")
        json.dumps(event)

    def test_unsupported_network_protocol_does_not_crash(self):
        event = parse_packet(Raw(load=b"malformed"), 1)
        self.assertEqual(event["parse_status"], "UNSUPPORTED")
        self.assertEqual(event["network_protocol"], "UNKNOWN")
        json.dumps(event)

    def test_malformed_packet_does_not_crash(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2", proto=17, len=100) / Raw(load=b"short")
        event = parse_packet(packet, 1)
        self.assertIn(event["parse_status"], {"INCOMPLETE", "MALFORMED"})
        self.assertIn("error", event)
        json.dumps(event)


if __name__ == "__main__":
    unittest.main()
