"""Small PCAP tests for the real command-line runner."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import main


class RunnerTests(unittest.TestCase):
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
        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80) / Raw(
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
