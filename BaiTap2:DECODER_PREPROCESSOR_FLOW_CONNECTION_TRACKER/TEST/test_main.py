"""Small PCAP tests for the real command-line runner."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import main


def tcp_packet(flags, timestamp, reverse=False, payload=b"", seq=100, ack=0):
    source, destination = ("10.0.0.2", "10.0.0.1") if reverse else ("10.0.0.1", "10.0.0.2")
    sport, dport = (80, 40000) if reverse else (40000, 80)
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=source, dst=destination) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        packet = packet / Raw(payload)
    packet.time = timestamp
    return packet


class RunnerTests(unittest.TestCase):
    def test_bad_packet_policy_and_unreadable_input(self):
        good = tcp_packet("PA", 1700000000, payload=b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        broken = Ether() / IP(src="10.0.0.9", dst="10.0.0.8") / TCP(sport=1, dport=2)
        broken[IP].ihl = 3
        broken.time = 1700000001
        marked, flows = self.run_pcap([broken, good])
        self.assertEqual([event["preprocess_status"] for event in marked], ["invalid", "valid"])
        self.assertEqual(marked[0]["processing_action"], "mark")
        self.assertIsNone(marked[0]["flow_id"])
        self.assertEqual(marked[0]["transport_protocol"], "UNKNOWN")
        self.assertEqual(len(flows), 1)
        skipped, flows = self.run_pcap([broken, good], "--invalid-policy", "skip")
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["packet_id"], 2)
        self.assertEqual(skipped[0]["processing_action"], "keep")
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["close_reason"], "eof")
        # A cut trailing record is reported, then the readable flow is exported.
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            pcap, events, flows_path = (directory / "cut.pcap", directory / "e.jsonl",
                                       directory / "f.jsonl")
            wrpcap(str(pcap), [good, good])
            pcap.write_bytes(pcap.read_bytes()[:-10])
            result = subprocess.run([sys.executable, "-B", str(Path(main.__file__)), "--pcap",
                                     str(pcap), "--output", str(events), "--flows-output",
                                     str(flows_path), "--udp-timeout", "1", "--tcp-timeout", "1"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            reported = [json.loads(line) for line in events.read_text().splitlines()]
            self.assertEqual(reported[0]["packet_id"], 1)
            # The cut trailing record is reported, then the readable flow is still exported.
            self.assertEqual(reported[-1]["parse_status"], "INCOMPLETE")
            self.assertIn("truncated", reported[-1]["error"])
            self.assertEqual(len([json.loads(line) for line in flows_path.read_text().splitlines()]), 1)
        for bad_options in (("--tcp-timeout", "0"), ("--udp-timeout", "nan"),
                            ("--max-decode-size", "0"), ("--invalid-policy", "drop")):
            with self.subTest(options=bad_options):
                with tempfile.TemporaryDirectory() as directory:
                    pcap = Path(directory) / "in.pcap"
                    wrpcap(str(pcap), [good])
                    result = subprocess.run([sys.executable, "-B", str(Path(main.__file__)),
                                             "--pcap", str(pcap), "--output", str(Path(directory) / "e.jsonl"),
                                             "--flows-output", str(Path(directory) / "f.jsonl"),
                                             *bad_options], capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 2)

    def test_bad_bytes_then_mime_pcap(self):
        bad = tcp_packet("PA", 1700000000, payload=(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ninvalid: \xff"))
        mime1 = tcp_packet("PA", 1700000001, payload=(
            b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8="))
        mime2 = tcp_packet("PA", 1700000002, payload=(
            b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n\r\nXin ch=C3=A0o"))
        for packet in (mime1, mime2):
            packet[TCP].sport = 40001
            packet[TCP].dport = 25
        events, flows = self.run_pcap([bad, mime1, mime2])
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["decode_status"], "PARTIAL")
        self.assertEqual(events[0]["preprocess_status"], "partial")
        self.assertEqual(events[1]["decoded_body"], "Hello")
        self.assertEqual(events[2]["decoded_body"], "Xin chào")
        self.assertEqual(events[1]["application_protocol"], "SMTP")
        self.assertEqual(events[1]["flow_id"], events[2]["flow_id"])
        self.assertNotEqual(events[0]["flow_id"], events[1]["flow_id"])
        self.assertEqual(len(flows), 2)
        self.assertTrue(all(flow["close_reason"] == "eof" for flow in flows))
        limited, _ = self.run_pcap([bad, mime1, mime2], "--max-decode-size", "16")
        self.assertEqual(len(limited), 3)
        self.assertTrue(all(event["decode_status"] == "PARTIAL" for event in limited))

    def test_end_to_end_http_tcp(self):
        form = b"name=Alice+Smith&literal=%2B"
        request = (b"POST /Search?q=%27%20OR%201%3D1 HTTP/1.1\r\nHost: EXAMPLE.TEST\r\n"
                   b"Content-Type: application/x-www-form-urlencoded\r\n"
                   + f"Content-Length: {len(form)}\r\n\r\n".encode() + form)
        body = b"&lt;script&gt;x&lt;/script&gt;"
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        base = 1700000000
        packets = [tcp_packet("S", base),
                   tcp_packet("SA", base + 1, True, seq=500, ack=101),
                   tcp_packet("A", base + 2, seq=101, ack=501),
                   tcp_packet("PA", base + 3, payload=request, seq=101, ack=501),
                   tcp_packet("PA", base + 4, True, response, seq=501, ack=101 + len(request)),
                   tcp_packet("FA", base + 5, seq=101 + len(request), ack=501 + len(response)),
                   tcp_packet("A", base + 6, True, seq=501 + len(response), ack=102 + len(request)),
                   tcp_packet("FA", base + 7, True, seq=501 + len(response), ack=102 + len(request)),
                   tcp_packet("A", base + 8, seq=102 + len(request), ack=502 + len(response))]
        events, flows = self.run_pcap(packets)
        self.assertEqual(len(events), 9)
        self.assertEqual(len({event["flow_id"] for event in events}), 1)
        self.assertEqual(events[2]["flow_state"], "ESTABLISHED")
        self.assertEqual(events[3]["http_target"], "/Search?q=%27%20OR%201%3D1")
        self.assertEqual(events[3]["decoded_http_target"], "/Search?q=' OR 1=1")
        self.assertEqual(events[3]["decoded_form"][0]["value"], "Alice Smith")
        self.assertEqual(events[3]["headers"]["host"], "example.test")
        self.assertEqual(events[4]["decoded_body"], "<script>x</script>")
        self.assertTrue(all(event["track_status"] == "OK" for event in events))
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["state"], "CLOSED")
        self.assertEqual(flows[0]["close_reason"], "tcp_fin")
        self.assertEqual(flows[0]["application_protocol"], "HTTP")
        self.assertEqual(flows[0]["byte_count"], sum(len(bytes(packet)) for packet in packets))
        self.assertEqual(flows[0]["packet_count"], 9)
        self.assertEqual(flows[0]["forward_packet_count"], 5)
        self.assertEqual(flows[0]["backward_packet_count"], 4)
        self.assertEqual(flows[0]["duration"], 8)

    def run_pcap(self, packets, *options):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            pcap = directory / "input.pcap"
            events = directory / "events.jsonl"
            flows = directory / "flows.jsonl"
            wrpcap(str(pcap), packets)
            command = [sys.executable, "-B", str(Path(main.__file__)), "--pcap", str(pcap),
                       "--output", str(events), "--flows-output", str(flows), *options]
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            return ([json.loads(line) for line in events.read_text().splitlines()],
                    [json.loads(line) for line in flows.read_text().splitlines()])

    def test_parser_reuse_smoke(self):
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80) / Raw(
            b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n")
        packet.time = 1700000000
        event, payload = main.packet_to_event(packet, 1)
        self.assertEqual(event["http_target"], "/hello")
        self.assertEqual(event["packet_length"], len(bytes(packet)))
        self.assertEqual(payload, bytes(packet[TCP].payload))
        events, _ = self.run_pcap([packet])
        self.assertEqual(events[0]["http_target"], "/hello")


if __name__ == "__main__":
    unittest.main()
