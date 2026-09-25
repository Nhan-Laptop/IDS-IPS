"""Packet capture entry points and the shared IDS parsing pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

from scapy.all import Packet, sniff
from scapy.error import Scapy_Exception

from parsers import parse_packet

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


def Capture_through_pcap(
    pcap_file: str,
    packet_handler: PacketHandler,
    *,
    count: int = 0,
) -> None:
    """Read packets from a PCAP file and pass them to the parser."""
    if not pcap_file or not pcap_file.strip():
        raise ValueError("pcap_file must not be empty")
    if not callable(packet_handler):
        raise ValueError("packet_handler must be callable")
    if count < 0:
        raise ValueError("count must be zero or greater")

    sniff(
        offline=pcap_file,
        prn=packet_handler,
        count=count,
        store=False,
    )


def _write_event(event: dict[str, Any], output: TextIO) -> None:
    """Write one normalized event as one JSON Lines record."""
    output.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    output.flush()


def handle_packet(packet: Packet) -> None:
    """Parse and print one packet as a normalized JSON-compatible event."""
    global _packet_id
    _packet_id += 1
    _write_event(parse_packet(packet, _packet_id), sys.stdout)


def make_packet_handler(output: TextIO, *, unknown_policy: str = "mark") -> PacketHandler:
    """Create a packet callback writing JSON Lines with its own packet ids.

    With ``unknown_policy="skip"`` the events of packets whose application
    protocol could not be identified are dropped instead of being written.
    Packet ids still follow the captured packet order, so a gap marks a
    skipped packet.
    """
    if unknown_policy not in UNKNOWN_POLICIES:
        raise ValueError("unknown_policy must be 'mark' or 'skip'")
    packet_id = 0

    def packet_handler(packet: Packet) -> None:
        nonlocal packet_id
        packet_id += 1
        event = parse_packet(packet, packet_id)
        if unknown_policy == "skip" and event["application_protocol"] == "UNKNOWN":
            return
        _write_event(event, output)

    return packet_handler


def _reset_packet_id() -> None:
    global _packet_id
    _packet_id = 0


def _capture_from_args(args: argparse.Namespace, packet_handler: PacketHandler) -> None:
    if args.interface is not None:
        Capture_through_interface(
            args.interface,
            packet_handler,
            count=args.count,
            timeout=args.timeout,
            packet_filter=args.packet_filter,
        )
    else:
        Capture_through_pcap(args.pcap, packet_handler, count=args.count)


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
    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output:
                handler = make_packet_handler(output, unknown_policy=args.unknown_policy)
                _capture_from_args(args, handler)
        elif args.unknown_policy == "mark":
            _capture_from_args(args, handle_packet)
        else:
            handler = make_packet_handler(sys.stdout, unknown_policy=args.unknown_policy)
            _capture_from_args(args, handler)
    except KeyboardInterrupt:
        print("\nCapture stopped.", file=sys.stderr)
        return 130
    except (OSError, Scapy_Exception, ValueError) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
