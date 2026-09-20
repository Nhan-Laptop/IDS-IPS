"""CLI checks using mocked live capture and a synthetic offline PCAP."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, UDP, wrpcap
from scapy.error import Scapy_Exception

import main


class CaptureCLITests(unittest.TestCase):
    def test_live_capture_uses_shared_handler(self):
        with patch("main.sniff") as sniff:
            result = main.main([
                "--interface", "test0", "--count", "2",
                "--timeout", "5", "--filter", "udp",
            ])
        self.assertEqual(result, 0)
        sniff.assert_called_once_with(
            iface="test0", prn=main.handle_packet, count=2,
            timeout=5, filter="udp", store=False,
        )

    def test_live_capture_defaults(self):
        with patch("main.sniff") as sniff:
            result = main.main(["--interface", "test0"])
        self.assertEqual(result, 0)
        sniff.assert_called_once_with(
            iface="test0", prn=main.handle_packet, count=0,
            timeout=None, filter=None, store=False,
        )

    def test_pcap_uses_shared_handler(self):
        with patch("main.sniff") as sniff:
            result = main.main(["--pcap", "sample.pcap", "--count", "2"])
        self.assertEqual(result, 0)
        sniff.assert_called_once_with(
            offline="sample.pcap", prn=main.handle_packet, count=2, store=False,
        )

    def test_invalid_arguments_do_not_start_capture(self):
        cases = [
            [],
            ["--interface", "test0", "--pcap", "sample.pcap"],
            ["--interface", "test0", "--count", "-1"],
            ["--interface", "test0", "--count", "abc"],
            ["--interface", "test0", "--timeout", "0"],
            ["--interface", "test0", "--timeout", "-1"],
            ["--pcap", "sample.pcap", "--timeout", "5"],
            ["--pcap", "sample.pcap", "--filter", "udp"],
        ]
        for argv in cases:
            with self.subTest(argv=argv), patch("main.sniff") as sniff:
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        main.main(argv)
                self.assertEqual(error.exception.code, 2)
                sniff.assert_not_called()

    def test_capture_errors_have_readable_messages(self):
        errors = [
            PermissionError("Insufficient capture permissions"),
            OSError("Interface not found"),
            Scapy_Exception("Capture setup failed"),
        ]
        for error in errors:
            with self.subTest(error=error):
                output = io.StringIO()
                with patch("main.sniff", side_effect=error), redirect_stderr(output):
                    result = main.main(["--interface", "test0"])
                self.assertEqual(result, 1)
                self.assertIn(f"Capture failed: {error}", output.getvalue())

    def test_interrupt_is_handled(self):
        output = io.StringIO()
        with patch("main.sniff", side_effect=KeyboardInterrupt):
            with redirect_stderr(output):
                result = main.main(["--interface", "test0"])
        self.assertEqual(result, 130)
        self.assertIn("Capture stopped.", output.getvalue())

    def test_handler_prints_capture_timestamp_and_summary(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / UDP()
        packet.time = 1700000000.125
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertIsNone(main.handle_packet(packet))
        self.assertEqual(output.getvalue(), f"{packet.time} {packet.summary()}\n")

    def test_real_pcap_playback_preserves_timestamp_and_count(self):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=12345, dport=12346)
        )
        packet.time = 1700000000.125
        with tempfile.TemporaryDirectory() as directory:
            pcap_file = str(Path(directory) / "sample.pcap")
            wrpcap(pcap_file, [packet, packet])
            for count, expected_lines in ((0, 2), (1, 1)):
                with self.subTest(count=count):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        result = main.main(["--pcap", pcap_file, "--count", str(count)])
                    self.assertEqual(result, 0)
                    lines = output.getvalue().splitlines()
                    self.assertEqual(len(lines), expected_lines)
                    for line in lines:
                        self.assertTrue(line.startswith("1700000000.125"))
                        self.assertIn("192.0.2.1", line)
                        self.assertIn("192.0.2.2", line)


if __name__ == "__main__":
    unittest.main()
