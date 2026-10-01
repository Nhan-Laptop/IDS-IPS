"""Check an event and give later modules consistent values."""

from datetime import datetime, timezone
from ipaddress import ip_address
import json
import math
import re


SCALAR_FIELDS = (
    "packet_id", "network_protocol", "payload_length", "parse_status",
    "tcp_sequence", "tcp_acknowledgment", "tcp_window", "body", "http_target",
    "http_method", "http_version", "status_code", "reason_phrase",
    "dns_transaction_id", "dns_is_response", "smtp_command", "smtp_argument",
    "smtp_status_code", "smtp_text", "decoded_http_target", "decoded_body",
)
FLAG_NAMES = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")


def parse_timestamp(value):
    """Accept ISO-8601 or epoch seconds; a naive datetime is treated as UTC."""
    if isinstance(value, bool):
        raise ValueError("invalid timestamp")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("timestamp must be finite")
        return datetime.fromtimestamp(value, timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp missing or invalid")
    date = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc)


def _domain(value):
    if not isinstance(value, str):
        raise ValueError("domain must be text")
    value = value.strip().lower()
    return value.rstrip(".") if value != "." else value


def preprocess_event(event, invalid_policy="mark"):
    if invalid_policy not in ("mark", "skip"):
        raise ValueError("invalid_policy must be mark or skip")
    invalid = []
    partial = []
    if not isinstance(event, dict):
        invalid.append("event must be a dictionary")
        event = {}
    result = {}
    # Replace non-JSON values rather than crashing when writing the result.
    for name, value in event.items():
        if not isinstance(name, str):
            invalid.append("event field names must be text")
            continue
        try:
            json.dumps(value, allow_nan=False)
            result[name] = value
        except (TypeError, ValueError, OverflowError, RecursionError):
            result[name] = None
            invalid.append(f"{name} is not JSON-compatible")
    for field in SCALAR_FIELDS:
        result.setdefault(field, None)

    for field in ("src_ip", "dst_ip"):
        try:
            value = result.get(field)
            if not isinstance(value, str):
                raise ValueError("IP must be text")
            result[field] = str(ip_address(value.strip()))
        except ValueError:
            result[field] = None
            invalid.append(f"{field} missing or invalid")
    for field in ("src_port", "dst_port"):
        value = result.get(field)
        if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
            try:
                value = int(value.strip())
            except ValueError:
                value = None
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 65535:
            result[field] = None
            invalid.append(f"{field} missing or outside 0..65535")
        else:
            result[field] = value
    try:
        result["timestamp"] = parse_timestamp(result.get("timestamp")).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        result["timestamp"] = None
        invalid.append("timestamp missing or invalid")

    protocol = result.get("transport_protocol")
    protocol = protocol.strip().upper() if isinstance(protocol, str) else "UNKNOWN"
    result["transport_protocol"] = protocol
    if protocol not in ("TCP", "UDP"):
        invalid.append("unsupported transport protocol")
    application = result.get("application_protocol", "UNKNOWN")
    application = application.strip().upper() if isinstance(application, str) else "UNKNOWN"
    if application not in ("HTTP", "DNS", "SMTP", "UNKNOWN"):
        partial.append(f"unsupported application protocol: {application}")
        application = "UNKNOWN"
    result["application_protocol"] = application
    network = result["network_protocol"]
    if isinstance(network, str):
        result["network_protocol"] = {"IPV4": "IPv4", "IPV6": "IPv6"}.get(network.strip().upper(), "UNKNOWN")

    for field in ("packet_length", "payload_length"):
        value = result.get(field)
        if value is None and field == "payload_length":
            partial.append("payload_length missing")
        elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
            invalid.append(f"{field} must be a non-negative integer")
            result[field] = None
    flags = result.get("tcp_flags", [])
    if flags is None:
        flags = []
    if not isinstance(flags, list):
        partial.append("tcp_flags must be a list")
        flags = []
    normalized_flags = []
    for flag in flags:
        if isinstance(flag, str) and flag.strip().upper() in FLAG_NAMES:
            normalized_flags.append(flag.strip().upper())
        else:
            partial.append("unsupported TCP flag")
    result["tcp_flags"] = [flag for flag in FLAG_NAMES if flag in normalized_flags]
    for field in ("tcp_sequence", "tcp_acknowledgment", "tcp_window"):
        value = result[field]
        limit = 65535 if field == "tcp_window" else 2**32 - 1
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= limit):
            result[field] = None
            partial.append(f"invalid {field}")

    headers = result.get("headers") or {}
    normalized_headers = {}
    if not isinstance(headers, dict):
        partial.append("headers must be a dictionary")
    else:
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                partial.append("header names and values must be text")
            else:
                normalized_headers[name.strip().lower()] = value.strip()
        if "host" in normalized_headers:
            normalized_headers["host"] = normalized_headers["host"].lower()
    result["headers"] = normalized_headers
    for field in ("dns_questions", "dns_answers"):
        records = result.get(field)
        if records is None:
            records = []
        if not isinstance(records, list):
            partial.append(f"{field} must be a list")
            records = []
        normalized = []
        for record in records:
            if not isinstance(record, dict):
                partial.append(f"invalid {field} record")
                continue
            record = dict(record)
            try:
                record["name"] = _domain(record.get("name"))
                if field == "dns_answers" and str(record.get("type", "")).upper() in ("CNAME", "NS", "PTR"):
                    record["data"] = _domain(record.get("data"))
            except ValueError as error:
                partial.append(str(error))
                record["name"] = None
            normalized.append(record)
        result[field] = normalized

    target = result.get("http_target")
    result["normalized_http_target"] = None
    if target is not None:
        if isinstance(target, str) and not any(char in target for char in "\r\n\x00"):
            result["normalized_http_target"] = re.sub(r"%[0-9a-fA-F]{2}", lambda m: m[0].upper(), target or "/")
        else:
            partial.append("invalid HTTP target")
    if result.get("parse_status") not in (None, "OK"):
        partial.append(f"parser status: {result['parse_status']}")
    if result.get("decode_status") in ("PARTIAL", "ERROR"):
        partial.append(result.get("decode_reason") or "decoding incomplete")

    result["preprocess_status"] = "invalid" if invalid else ("partial" if partial else "valid")
    result["trackable"] = not invalid
    result["processing_action"] = "skip" if invalid and invalid_policy == "skip" else (
        "mark" if invalid or partial else "keep")
    result["reason"] = "; ".join(str(reason) for reason in invalid + partial) or None
    return result
