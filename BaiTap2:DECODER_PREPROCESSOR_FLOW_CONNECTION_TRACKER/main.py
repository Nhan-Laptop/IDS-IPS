"""Homework 2: reuse the first parser, then process each packet."""

import argparse
import json
import math
from pathlib import Path
import sys

from scapy.all import PcapReader, TCP, UDP

from scapy.error import Scapy_Exception

from decoder import decode_event
from preprocessor import preprocess_event
from flow_tracker import finish_flows, new_tracker, track_event

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


def process_event(event, tracker, raw_payload=None, max_decode_size=65536, invalid_policy="mark"):
    """One bad packet must not prevent the following packet from being processed."""
    try:
        decoded = decode_event(event, raw_payload, max_decode_size)
    except Exception as error:
        decoded = dict(event) if isinstance(event, dict) else {}
        decoded.update(decode_status="ERROR", decode_reason=f"decoder failed: {error}")
    try:
        processed = preprocess_event(decoded, invalid_policy)
    except Exception as error:
        return {"preprocess_status": "invalid", "trackable": False,
                "processing_action": "skip" if invalid_policy == "skip" else "mark",
                "reason": f"preprocessor failed: {error}", "track_status": "ERROR",
                "flow_id": None, "direction": None, "flow_state": None}, []
    try:
        return track_event(tracker, processed)
    except Exception as error:
        processed.update(preprocess_status="invalid", trackable=False, track_status="ERROR",
                         processing_action="skip" if invalid_policy == "skip" else "mark",
                         reason=f"tracker failed: {error}", flow_id=None, direction=None, flow_state=None)
        return processed, []


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

    tracker = new_tracker(args.tcp_timeout, args.udp_timeout)
    exit_code = 0
    try:
        with PcapReader(args.pcap) as packets, \
                open(args.output, "w", encoding="utf-8") as events, \
                open(args.flows_output, "w", encoding="utf-8") as flows:
            packet_id = 0
            end_reason = "eof"
            while True:
                try:
                    packet = next(packets)
                except StopIteration:
                    break
                except KeyboardInterrupt:
                    end_reason = "interrupted"
                    exit_code = 130
                    break
                except Exception as error:
                    # An unreadable binary record cannot safely be resynchronized.
                    packet_id += 1
                    bad = error_event(packet_id, f"unreadable PCAP record: {error}", status="INCOMPLETE")
                    event, _ = process_event(bad, tracker, invalid_policy=args.invalid_policy)
                    if event["processing_action"] != "skip":
                        write_jsonl(events, event)
                    end_reason = "read_error"
                    break
                packet_id += 1
                event, payload = packet_to_event(packet, packet_id)
                event, completed = process_event(event, tracker, payload, args.max_decode_size, args.invalid_policy)
                if event["processing_action"] != "skip":
                    write_jsonl(events, event)
                for flow in completed:
                    write_jsonl(flows, flow)
            for flow in finish_flows(tracker, end_reason):
                write_jsonl(flows, flow)
    except (OSError, ValueError, Scapy_Exception) as error:
        print(f"Processing failed: {error}", file=sys.stderr)
        return 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
