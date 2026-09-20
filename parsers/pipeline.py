"""Layered packet-to-event parsing for the IDS."""

from __future__ import annotations

import base64
import re
import struct
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from .errors import IncompletePacket, UnsupportedProtocol


_HTTP_VERSION = re.compile(rb"^HTTP/1\.[01]\s")
_HTTP_REQUEST = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+([^\s]+)\s+HTTP/1\.[01](?:\r?\n|$)"
)
_HTTP_RESPONSE = re.compile(
    rb"^HTTP/1\.[01]\s+(\d{3})(?:\s+([^\r\n]*))?(?:\r?\n|$)"
)
_SMTP_COMMAND = re.compile(
    rb"^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|RSET|NOOP|QUIT|VRFY|AUTH)(?:[ \t]+|:)?([^\r\n]*)(?:\r?\n|$)",
    re.IGNORECASE,
)
_SMTP_RESPONSE = re.compile(rb"^(\d{3})(?:[ -]([^\r\n]*))?(?:\r?\n|$)")


def parse_packet(packet: Packet, packet_id: int) -> dict[str, Any]:
    """Convert one Scapy packet into a JSON-compatible normalized event.

    The stages are deliberately explicit: IPv4 network parsing, TCP/UDP
    transport parsing, application detection, and application parsing. Any
    malformed or unsupported packet becomes an event instead of stopping
    capture.
    """
    event: dict[str, Any] = {
        "packet_id": packet_id,
        "timestamp": _timestamp(packet),
        "src_ip": None,
        "dst_ip": None,
        "network_protocol": "UNKNOWN",
        "transport_protocol": "UNKNOWN",
        "src_port": None,
        "dst_port": None,
        "tcp_flags": [],
        "tcp_sequence": None,
        "tcp_acknowledgment": None,
        "tcp_window": None,
        "application_protocol": "UNKNOWN",
        "payload_length": 0,
    }

    try:
        network = _parse_ipv4(packet)
        event.update(
            src_ip=network["src_ip"],
            dst_ip=network["dst_ip"],
            network_protocol="IPv4",
        )
        transport = _parse_transport(network["payload"], packet)
        event.update(
            transport_protocol=transport["transport_protocol"],
            src_port=transport["src_port"],
            dst_port=transport["dst_port"],
            payload_length=len(transport["payload"]),
            tcp_flags=transport.get("tcp_flags", []),
            tcp_sequence=transport.get("tcp_sequence"),
            tcp_acknowledgment=transport.get("tcp_acknowledgment"),
            tcp_window=transport.get("tcp_window"),
        )
        application_protocol = detect_application_protocol(
            transport["payload"], transport["src_port"], transport["dst_port"], packet
        )
        event["application_protocol"] = application_protocol
        event.update(
            parse_application_payload(
                application_protocol,
                transport["payload"],
                packet,
            )
        )
    except UnsupportedProtocol as error:
        event["error"] = str(error)
        event["parse_status"] = "UNSUPPORTED"
    except IncompletePacket as error:
        event["error"] = str(error)
        event["parse_status"] = "INCOMPLETE"
    except (ValueError, TypeError, struct.error, UnicodeError) as error:
        event["error"] = str(error)
        event["parse_status"] = "MALFORMED"
    except Exception as error:  # defensive boundary for untrusted packet data
        event["error"] = f"unexpected parser error: {error}"
        event["parse_status"] = "MALFORMED"

    event.setdefault("parse_status", "OK")
    return _json_compatible(event)


def _timestamp(packet: Packet) -> str | None:
    """Return an ISO-8601 UTC timestamp when Scapy supplied one."""
    value = getattr(packet, "time", None)
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _parse_ipv4(packet: Packet) -> dict[str, Any]:
    """Extract the IPv4 layer and its raw payload."""
    if not packet.haslayer(IP):
        raise UnsupportedProtocol("IPv4 header is missing")

    ip = packet.getlayer(IP)
    if ip is None or not isinstance(ip, IP):
        raise ValueError("invalid IPv4 header")

    version = 4 if ip.version is None else int(ip.version)
    if version != 4:
        raise UnsupportedProtocol("unsupported network protocol")

    header_words = 5 if ip.ihl is None else int(ip.ihl)
    if header_words < 5:
        raise ValueError("invalid IPv4 header length")
    if ip.len is not None and int(ip.len) < header_words * 4:
        raise ValueError("invalid IPv4 total length")

    payload = bytes(ip.payload) if ip.payload is not None else b""
    expected_payload_length = None if ip.len is None else int(ip.len) - header_words * 4
    if expected_payload_length is not None and len(payload) < expected_payload_length:
        raise IncompletePacket("truncated IPv4 payload")
    if expected_payload_length is not None:
        payload = payload[:expected_payload_length]

    return {
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "payload": payload,
    }


def _parse_transport(payload: bytes, packet: Packet) -> dict[str, Any]:
    """Parse TCP or UDP using Scapy's decoded transport layer."""
    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        if tcp is None:
            raise ValueError("invalid TCP header")

        header_words = 5 if tcp.dataofs is None else int(tcp.dataofs)
        if header_words < 5:
            raise ValueError("invalid TCP header length")
        if len(payload) < header_words * 4:
            raise IncompletePacket("truncated TCP header")

        tcp_payload = bytes(tcp.payload) if tcp.payload is not None else b""
        return {
            "transport_protocol": "TCP",
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "payload": tcp_payload,
            "tcp_flags": _tcp_flags(tcp.flags),
            "tcp_sequence": int(tcp.seq),
            "tcp_acknowledgment": int(tcp.ack),
            "tcp_window": int(tcp.window),
        }

    if packet.haslayer(UDP):
        udp = packet.getlayer(UDP)
        if udp is None:
            raise ValueError("invalid UDP header")
        if udp.len is not None and int(udp.len) < 8:
            raise ValueError("invalid UDP length")
        if udp.len is not None and len(payload) < int(udp.len):
            raise IncompletePacket("truncated UDP packet")

        udp_payload = bytes(udp.payload) if udp.payload is not None else b""
        if udp.len is not None:
            udp_payload = udp_payload[: int(udp.len) - 8]
        return {
            "transport_protocol": "UDP",
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport),
            "payload": udp_payload,
        }

    ip = packet.getlayer(IP)
    if ip is not None and int(ip.proto or 0) == 6:
        raise IncompletePacket("truncated TCP header")
    if ip is not None and int(ip.proto or 0) == 17:
        raise IncompletePacket("truncated UDP header")
    raise UnsupportedProtocol("unsupported transport protocol")


def _tcp_flags(flags: Any) -> list[str]:
    """Return stable, JSON-compatible TCP flag names."""
    names = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
    flag_value = int(flags)
    return [name for index, name in enumerate(names) if flag_value & (1 << index)]


def detect_application_protocol(
    payload: bytes,
    src_port: int | None,
    dst_port: int | None,
    packet: Packet | None = None,
) -> str:
    """Detect HTTP, DNS, or SMTP from payload and conventional ports."""
    if packet is not None and packet.haslayer(DNS):
        return "DNS"
    if src_port in (53, 5353) or dst_port in (53, 5353):
        return "DNS"

    stripped = payload.lstrip()
    if _looks_like_dns(stripped):
        return "DNS"
    if _HTTP_REQUEST.match(stripped) or _HTTP_RESPONSE.match(stripped):
        return "HTTP"
    if src_port in (80, 8080, 8000, 8008, 8888) or dst_port in (80, 8080, 8000, 8008, 8888):
        if _looks_like_http(stripped):
            return "HTTP"

    if _SMTP_COMMAND.match(stripped) or _SMTP_RESPONSE.match(stripped):
        return "SMTP"
    if src_port in (25, 465, 587, 2525) or dst_port in (25, 465, 587, 2525):
        if _looks_like_smtp(stripped):
            return "SMTP"

    return "UNKNOWN"


def _looks_like_http(payload: bytes) -> bool:
    return bool(
        _HTTP_REQUEST.match(payload)
        or _HTTP_RESPONSE.match(payload)
        or _HTTP_VERSION.match(payload)
    )


def _looks_like_dns(payload: bytes) -> bool:
    """Validate enough of a DNS header to avoid port-only false positives."""
    if len(payload) < 12:
        return False
    try:
        dns = DNS(payload)
        opcode = int(dns.opcode or 0)
        counts = [
            int(dns.qdcount or 0),
            int(dns.ancount or 0),
            int(dns.nscount or 0),
            int(dns.arcount or 0),
        ]
    except Exception:
        return False
    return opcode <= 5 and all(0 <= count <= 100 for count in counts) and any(counts)



def _looks_like_smtp(payload: bytes) -> bool:
    return bool(_SMTP_COMMAND.match(payload) or _SMTP_RESPONSE.match(payload))


def parse_application_payload(
    application_protocol: str,
    payload: bytes,
    packet: Packet | None = None,
) -> dict[str, Any]:
    """Parse an application payload after it has been identified."""
    if application_protocol == "HTTP":
        return _parse_http(payload)
    if application_protocol == "DNS":
        return _parse_dns(payload, packet)
    if application_protocol == "SMTP":
        return _parse_smtp(payload)
    return {}


def _parse_http(payload: bytes) -> dict[str, Any]:
    header_bytes, separator, body = payload.partition(b"\r\n\r\n")
    if not separator:
        header_bytes, separator, body = payload.partition(b"\n\n")
    lines = header_bytes.splitlines()
    if not lines:
        return {"parse_status": "MALFORMED", "error": "empty HTTP payload"}

    first_line = lines[0].decode("iso-8859-1")
    headers = _parse_text_headers(lines[1:])
    request = _HTTP_REQUEST.match(lines[0])
    response = _HTTP_RESPONSE.match(lines[0])
    result: dict[str, Any] = {
        "headers": headers,
        "body": _decode_payload(body),
    }
    if request:
        result.update(
            http_message_type="request",
            http_method=request.group(1).decode("ascii"),
            http_target=request.group(2).decode("iso-8859-1"),
            http_version=first_line.split()[-1],
        )
    elif response:
        result.update(
            http_message_type="response",
            http_version=first_line.split()[0],
            status_code=int(response.group(1)),
            reason_phrase=(response.group(2) or b"").decode("iso-8859-1"),
        )
    else:
        result.update(parse_status="MALFORMED", error="invalid HTTP start line")
    return result


def _parse_text_headers(lines: list[bytes]) -> dict[str, str]:
    headers: dict[str, str] = {}
    current_name: str | None = None
    for line in lines:
        if not line:
            continue
        if line[:1] in (b" ", b"\t") and current_name is not None:
            headers[current_name] += " " + line.decode("iso-8859-1").strip()
            continue
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        current_name = name.decode("iso-8859-1").strip().lower()
        headers[current_name] = value.decode("iso-8859-1").strip()
    return headers


def _parse_dns(payload: bytes, packet: Packet | None) -> dict[str, Any]:
    dns = packet.getlayer(DNS) if packet is not None and packet.haslayer(DNS) else None
    if dns is None and payload:
        try:
            dns = DNS(payload)
        except Exception as error:
            return {"parse_status": "MALFORMED", "error": f"DNS decode failed: {error}"}
    if dns is None:
        return {"parse_status": "MALFORMED", "error": "empty DNS payload"}

    questions = _dns_records(dns.qd, DNSQR)
    answers = _dns_records(dns.an, DNSRR)
    question_count = len(questions) if dns.qdcount is None else int(dns.qdcount)
    answer_count = len(answers) if dns.ancount is None else int(dns.ancount)
    result: dict[str, Any] = {
        "dns_transaction_id": int(dns.id),
        "dns_is_response": bool(dns.qr),
        "dns_questions": [],
        "dns_answers": [],
    }
    for question in questions[:question_count]:
        result["dns_questions"].append(
            {"name": _dns_name(question.qname), "type": _dns_qtype(question.qtype)}
        )
    for answer in answers[:answer_count]:
        result["dns_answers"].append(
            {
                "name": _dns_name(answer.rrname),
                "type": _dns_qtype(answer.type),
                "ttl": int(answer.ttl),
                "data": _dns_rdata(answer),
            }
        )
    return result


def _dns_records(value: Any, record_type: type[Any]) -> list[Any]:
    """Normalize Scapy's DNS packet-list fields for predictable iteration."""
    if value is None:
        return []
    if isinstance(value, record_type):
        return [value]
    try:
        values = list(value)
    except TypeError:
        values = [value]
    return [item for item in values if isinstance(item, record_type)]


def _dns_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b".").decode("utf-8", errors="replace")
    return str(value).rstrip(".")


def _dns_qtype(value: Any) -> str:
    numeric = int(value)
    names = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
    }
    return names.get(numeric, str(numeric))


def _dns_rdata(answer: DNSRR) -> Any:
    value = answer.rdata
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _parse_smtp(payload: bytes) -> dict[str, Any]:
    line = payload.splitlines()[0] if payload.splitlines() else payload
    command = _SMTP_COMMAND.match(line + (b"\r\n" if b"\r\n" not in line else b""))
    response = _SMTP_RESPONSE.match(line + (b"\r\n" if b"\r\n" not in line else b""))
    if command:
        return {
            "smtp_message_type": "command",
            "smtp_command": command.group(1).decode("ascii").upper(),
            "smtp_argument": (command.group(2) or b"").decode("iso-8859-1").strip(),
        }
    if response:
        return {
            "smtp_message_type": "response",
            "smtp_status_code": int(response.group(1)),
            "smtp_text": (response.group(2) or b"").decode("iso-8859-1"),
        }
    return {"parse_status": "MALFORMED", "error": "invalid SMTP line"}


def _decode_payload(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def _json_compatible(value: Any) -> Any:
    """Convert Scapy/bytes values recursively into JSON-compatible values."""
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return {"base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
