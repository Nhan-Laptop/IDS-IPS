"""Normalized IDS event schema for the raw-packet-free output contract.

Every parser stage emits one dictionary with the same common fields and the
same value types. Protocol parsers only add their documented optional fields,
so the later detection engine can work with events without touching Scapy
packets or raw payload bytes.
"""

from __future__ import annotations

import json
from typing import Any


COMMON_EVENT_FIELDS: tuple[str, ...] = (
    "packet_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "network_protocol",
    "transport_protocol",
    "src_port",
    "dst_port",
    "tcp_flags",
    "tcp_sequence",
    "tcp_acknowledgment",
    "tcp_window",
    "application_protocol",
    "payload_length",
    "parse_status",
)

HTTP_EVENT_FIELDS: tuple[str, ...] = (
    "http_message_type",
    "http_method",
    "http_target",
    "http_version",
    "status_code",
    "reason_phrase",
    "headers",
    "body",
)

DNS_EVENT_FIELDS: tuple[str, ...] = (
    "dns_transaction_id",
    "dns_is_response",
    "dns_questions",
    "dns_answers",
)

SMTP_EVENT_FIELDS: tuple[str, ...] = (
    "smtp_message_type",
    "smtp_command",
    "smtp_argument",
    "smtp_status_code",
    "smtp_text",
)

ERROR_EVENT_FIELDS: tuple[str, ...] = ("error",)

NETWORK_PROTOCOLS = ("IPv4", "UNKNOWN")
TRANSPORT_PROTOCOLS = ("TCP", "UDP", "UNKNOWN")
APPLICATION_PROTOCOLS = ("HTTP", "DNS", "SMTP", "UNKNOWN")
PARSE_STATUSES = ("OK", "UNSUPPORTED", "INCOMPLETE", "MALFORMED")
TCP_FLAG_NAMES = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")

ALLOWED_EVENT_FIELDS = frozenset(
    COMMON_EVENT_FIELDS
    + HTTP_EVENT_FIELDS
    + DNS_EVENT_FIELDS
    + SMTP_EVENT_FIELDS
    + ERROR_EVENT_FIELDS
)


def validate_event(event: Any) -> list[str]:
    """Return the schema problems of one event; an empty list means valid."""
    if not isinstance(event, dict):
        return [f"event must be a dict, got {type(event).__name__}"]

    problems: list[str] = []
    for field in COMMON_EVENT_FIELDS:
        if field not in event:
            problems.append(f"missing common field: {field}")

    undocumented = sorted(set(event) - ALLOWED_EVENT_FIELDS)
    if undocumented:
        problems.append(f"undocumented fields: {', '.join(undocumented)}")

    packet_id = event.get("packet_id")
    if not isinstance(packet_id, int) or isinstance(packet_id, bool) or packet_id < 1:
        problems.append("packet_id must be a positive integer")

    if not _is_optional_text(event.get("timestamp")):
        problems.append("timestamp must be a string or null")
    for field in ("src_ip", "dst_ip"):
        if not _is_optional_text(event.get(field)):
            problems.append(f"{field} must be a string or null")
    for field in ("src_port", "dst_port"):
        if not _is_optional_port(event.get(field)):
            problems.append(f"{field} must be a port number or null")

    _check_choice(event, "network_protocol", NETWORK_PROTOCOLS, problems)
    _check_choice(event, "transport_protocol", TRANSPORT_PROTOCOLS, problems)
    _check_choice(event, "application_protocol", APPLICATION_PROTOCOLS, problems)
    _check_choice(event, "parse_status", PARSE_STATUSES, problems)

    flags = event.get("tcp_flags")
    if not isinstance(flags, list) or any(
        not isinstance(flag, str) or flag not in TCP_FLAG_NAMES for flag in flags
    ):
        problems.append("tcp_flags must be a list of TCP flag names")

    payload_length = event.get("payload_length")
    if (
        not isinstance(payload_length, int)
        or isinstance(payload_length, bool)
        or payload_length < 0
    ):
        problems.append("payload_length must be a non-negative integer")

    try:
        json.dumps(event)
    except (TypeError, ValueError) as error:
        problems.append(f"event is not JSON-compatible: {error}")

    return problems


def _is_optional_text(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _is_optional_port(value: Any) -> bool:
    if value is None:
        return True
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def _check_choice(
    event: dict[str, Any],
    field: str,
    allowed: tuple[str, ...],
    problems: list[str],
) -> None:
    if event.get(field) not in allowed:
        problems.append(f"{field} must be one of: {', '.join(allowed)}")
