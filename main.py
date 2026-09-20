"""Packet capture entry points for the IDS project."""

import argparse
import sys
from collections.abc import Callable
from typing import Any

from scapy.all import Packet, sniff
from scapy.error import Scapy_Exception


PacketHandler = Callable[[Packet], Any]


def Capture_through_interface(
    interface: str,
    packet_handler: PacketHandler,
    *,
    count: int = 0,
    timeout: int | None = None,
    packet_filter: str | None = None,
) -> None:
   
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


def handle_packet(packet: Packet) -> None:
    """Temporary shared handler until the parsing pipeline is implemented."""
    print(f"{packet.time} {packet.summary()}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture packets for the IDS.")
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
    args = parser.parse_args(argv)

    if args.count < 0:
        parser.error("--count must be zero or greater")
    if args.timeout is not None and args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.pcap is not None and (
        args.timeout is not None or args.packet_filter is not None
    ):
        parser.error("--timeout and --filter are only supported with --interface")

    try:
        if args.interface is not None:
            Capture_through_interface(
                args.interface,
                handle_packet,
                count=args.count,
                timeout=args.timeout,
                packet_filter=args.packet_filter,
            )
        else:
            Capture_through_pcap(args.pcap, handle_packet, count=args.count)
    except KeyboardInterrupt:
        print("\nCapture stopped.", file=sys.stderr)
        return 130
    except (OSError, Scapy_Exception, ValueError) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
