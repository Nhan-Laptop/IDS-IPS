"""Homework 2: reuse the first parser, then process each packet."""

import argparse
import json
import math
from pathlib import Path
import sys

from scapy.all import PcapReader, TCP, UDP

# The Homework 1 directory is not a normal Python package name.
HOMEWORK1 = Path(__file__).resolve().parent.parent / "BaiTap1:Packet_CAPTURER_AND_PARSER"
sys.path.insert(0, str(HOMEWORK1))
from parsers import error_event, parse_packet


def packet_to_event(packet, packet_id):
    """Keep the old event and supply original bytes separately to the decoder."""
    try:
        event = parse_packet(packet, packet_id)
        event["packet_length"] = len(bytes(packet))
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        payload = bytes(transport.payload) if transport is not None else b""
        # Do not include padding beyond the parser's transport payload length.
        payload = payload[:event["payload_length"]]
        return event, payload
    except Exception as error:
        event = error_event(packet_id, f"packet conversion failed: {error}")
        event["packet_length"] = None
        return event, b""


def write_jsonl(output, record):
    output.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
    output.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Homework 2: decode, preprocess and track a PCAP.")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output", default="events.jsonl")
    parser.add_argument("--flows-output", default="flows.jsonl")
    parser.add_argument("--tcp-timeout", type=float, default=120)
    parser.add_argument("--udp-timeout", type=float, default=30)
    parser.add_argument("--max-decode-size", type=int, default=65536)
    parser.add_argument("--invalid-policy", choices=("mark", "skip"), default="mark")
    args = parser.parse_args(argv)
    for name in ("tcp_timeout", "udp_timeout"):
        value = getattr(args, name)
        if not math.isfinite(value) or value <= 0:
            parser.error(f"--{name.replace('_', '-')} must be a finite positive number")
    if args.max_decode_size <= 0:
        parser.error("--max-decode-size must be positive")
    paths = [Path(path).resolve() for path in (args.pcap, args.output, args.flows_output)]
    if len(set(paths)) != 3:
        parser.error("input, event output and flow output must be different files")

    try:
        with PcapReader(args.pcap) as packets, \
                open(args.output, "w", encoding="utf-8") as events, \
                open(args.flows_output, "w", encoding="utf-8") as flows:
            for packet_id, packet in enumerate(packets, 1):
                event, payload = packet_to_event(packet, packet_id)
                write_jsonl(events, event)
    except (OSError, ValueError) as error:
        print(f"Processing failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
