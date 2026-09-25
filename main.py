"""Packet capture entry points and the shared IDS parsing pipeline."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections.abc import Callable
from typing import Any, TextIO

from scapy.all import Packet, sniff
from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from parsers import error_event, parse_packet

PacketHandler = Callable[[Packet], Any]
_packet_id = 0
UNKNOWN_POLICIES = ("mark", "skip")


def Capture_through_interface(
    interface: str,
    packet_handler: PacketHandler,
    *,
    count: int = 0,
    timeout: int | None = None,
    packet_filter: str | None = None,
) -> None:
    """Capture packets from a network interface and pass them to the parser.

    The callback is invoked once for each packet, so live traffic enters the
    same parsing pipeline as packets imported from a PCAP file.
    """
    if not interface or not interface.strip():
        raise ValueError("interface must not be empty")
    if not callable(packet_handler):
        raise ValueError("packet_handler must be callable")
    if count < 0:
        raise ValueError("count must be zero or greater")
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    sniff(
        iface=interface,
        prn=packet_handler,
        count=count,
        timeout=timeout,
        filter=packet_filter,
        store=False,
    )


def _is_short_record(packet: Packet, snaplen: int) -> bool:
    """Report whether a record holds fewer bytes than its own capture length.

    A capture that was limited by the file's snap length is normal and is not
    reported; a record that should have been complete but is short means the
    PCAP file itself was truncated.
    """
    wirelen = getattr(packet, "wirelen", None)
    if wirelen is None:
        return False
    captured = len(bytes(packet))
    return captured < int(wirelen) <= int(snaplen or 0)


def Capture_through_pcap(
    pcap_file: str,
    packet_handler: PacketHandler,
    *,
    count: int = 0,
    packet_error_handler: Callable[[str], Any] | None = None,
) -> None:
    """Read packets from a PCAP file and pass them to the parser.

    Truncated files and unreadable records do not stop the program: every
    readable packet is still delivered, and the problem is reported through
    ``packet_error_handler`` when one is given.
    """
    if not pcap_file or not pcap_file.strip():
        raise ValueError("pcap_file must not be empty")
    if not callable(packet_handler):
        raise ValueError("packet_handler must be callable")
    if packet_error_handler is not None and not callable(packet_error_handler):
        raise ValueError("packet_error_handler must be callable")
    if count < 0:
        raise ValueError("count must be zero or greater")

    processed = 0
    with PcapReader(pcap_file) as reader:
        while count == 0 or processed < count:
            try:
                packet = next(reader)
            except StopIteration:
                break  # normal end of file, including a truncated trailing record
            except (OSError, Scapy_Exception, struct.error, ValueError) as error:
                if packet_error_handler is not None:
                    detail = str(error).strip() or error.__class__.__name__
                    packet_error_handler(f"unreadable PCAP record ({detail})")
                break
            processed += 1
            packet_handler(packet)
            if packet_error_handler is not None and _is_short_record(
                packet, getattr(reader, "snaplen", 0)
            ):
                packet_error_handler(
                    "truncated PCAP packet "
                    f"(captured {len(bytes(packet))} of "
                    f"{getattr(packet, 'wirelen', 0)} bytes)"
                )


def _write_event(event: dict[str, Any], output: TextIO) -> None:
    """Write one normalized event as one JSON Lines record."""
    output.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    output.flush()


def _parse_safely(packet: Packet, packet_id: int) -> dict[str, Any]:
    """Parse one packet, containing unexpected parser failures as events."""
    try:
        return parse_packet(packet, packet_id)
    except Exception as error:  # one bad packet must never stop the capture
        return error_event(packet_id, f"parser failure contained: {error}")


def handle_packet_error(message: str) -> None:
    """Log a capture or read failure as one JSON Lines event on stdout."""
    global _packet_id
    _packet_id += 1
    _write_event(error_event(_packet_id, message, status="INCOMPLETE"), sys.stdout)


def handle_packet(packet: Packet) -> None:
    """Parse and print one packet as a normalized JSON-compatible event."""
    global _packet_id
    _packet_id += 1
    _write_event(_parse_safely(packet, _packet_id), sys.stdout)


class PacketEventWriter:
    """Callable packet callback that writes normalized JSON Lines events."""

    def __init__(self, output: TextIO, *, unknown_policy: str = "mark") -> None:
        if unknown_policy not in UNKNOWN_POLICIES:
            raise ValueError("unknown_policy must be 'mark' or 'skip'")
        self.output = output
        self.unknown_policy = unknown_policy
        self.packet_id = 0
        self.written = 0

    def __call__(self, packet: Packet) -> None:
        self.packet_id += 1
        self.write_event(_parse_safely(packet, self.packet_id))

    def write_event(self, event: dict[str, Any]) -> None:
        """Write one event unless the unknown policy skips it."""
        if self.unknown_policy == "skip" and event["application_protocol"] == "UNKNOWN":
            return
        _write_event(event, self.output)
        self.written += 1

    def write_error(self, message: str, *, status: str = "INCOMPLETE") -> None:
        """Record a capture or read failure as one JSON Lines event."""
        self.packet_id += 1
        _write_event(error_event(self.packet_id, message, status=status), self.output)
        self.written += 1


def make_packet_handler(output: TextIO, *, unknown_policy: str = "mark") -> PacketHandler:
    """Create a packet callback writing JSON Lines with its own packet ids.

    With ``unknown_policy="skip"`` the events of packets whose application
    protocol could not be identified are dropped instead of being written.
    Packet ids still follow the captured packet order, so a gap marks a
    skipped packet.
    """
    return PacketEventWriter(output, unknown_policy=unknown_policy)


def _reset_packet_id() -> None:
    global _packet_id
    _packet_id = 0


def _capture_from_args(
    args: argparse.Namespace,
    packet_handler: PacketHandler,
    packet_error_handler: Callable[[str], Any] | None = None,
) -> None:
    """Run the capture source selected on the command line."""
    if args.interface is not None:
        Capture_through_interface(
            args.interface,
            packet_handler,
            count=args.count,
            timeout=args.timeout,
            packet_filter=args.packet_filter,
        )
    else:
        Capture_through_pcap(
            args.pcap,
            packet_handler,
            count=args.count,
            packet_error_handler=packet_error_handler,
        )

def _append_capture_failure(
    output_path: str | None,
    writer: PacketEventWriter | None,
    message: str,
) -> None:
    """Append a capture failure as one JSON Lines event when logging to a file."""
    if not output_path:
        return
    packet_id = 1 if writer is None else writer.packet_id + 1
    try:
        with open(output_path, "a", encoding="utf-8") as output:
            _write_event(error_event(packet_id, message), output)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    """Parse command-line arguments and run one capture source."""
    parser = argparse.ArgumentParser(description="Capture and parse packets for the IDS.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="Network interface, for example eth0")
    source.add_argument("--pcap", help="Path to a PCAP file")
    parser.add_argument(
        "--count", type=int, default=0, help="Packet limit (0 means no limit)"
    )
    parser.add_argument(
        "--timeout", type=int, help="Stop live capture after this many seconds"
    )
    parser.add_argument(
        "--filter", dest="packet_filter", help="BPF filter for live capture"
    )
    parser.add_argument(
        "--output", help="JSON Lines output file (default: print events to stdout)"
    )
    parser.add_argument(
        "--unknown-policy",
        choices=UNKNOWN_POLICIES,
        default="mark",
        help="mark unknown application protocols or skip their events",
    )
    args = parser.parse_args(argv)

    if args.count < 0:
        parser.error("--count must be zero or greater")
    if args.timeout is not None and args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.pcap is not None and (
        args.timeout is not None or args.packet_filter is not None
    ):
        parser.error("--timeout and --filter are only supported with --interface")

    _reset_packet_id()
    writer: PacketEventWriter | None = None
    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output:
                writer = PacketEventWriter(output, unknown_policy=args.unknown_policy)
                _capture_from_args(args, writer, writer.write_error)
        elif args.unknown_policy == "mark":
            _capture_from_args(args, handle_packet, handle_packet_error)
        else:
            writer = PacketEventWriter(sys.stdout, unknown_policy=args.unknown_policy)
            _capture_from_args(args, writer, writer.write_error)
    except KeyboardInterrupt:
        print("\nCapture stopped.", file=sys.stderr)
        _append_capture_failure(args.output, writer, "capture interrupted")
        return 130
    except (OSError, Scapy_Exception, ValueError) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        _append_capture_failure(args.output, writer, f"capture failed: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
