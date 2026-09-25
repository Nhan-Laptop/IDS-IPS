"""Packet captures for the mandatory test cases of assignment section 9.

The evidence generator (``make_test_pcaps.py``) and the automated suite
(``test_mandatory_cases.py``) both build their captures from this module, so
the recorded evidence and the tests cannot drift apart.

Each builder returns the packet list for one mandatory test case:

    TCP handshake, TCP data, UDP, HTTP GET, HTTP POST, HTTP response,
    DNS query, DNS response, SMTP command, SMTP response, unknown protocol,
    malformed packet
"""

from __future__ import annotations

from collections.abc import Callable

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Packet, Raw, TCP, UDP

SRC = "10.0.0.1"
DST = "10.0.0.2"


def _eth() -> Ether:
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def tcp_handshake() -> list[Packet]:
    """SYN, SYN/ACK and ACK for one connection."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=80, flags="S", seq=1000),
        _eth()
        / IP(src=DST, dst=SRC)
        / TCP(sport=80, dport=40000, flags="SA", seq=5000, ack=1001),
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=80, flags="A", seq=1001, ack=5001),
    ]


def tcp_data() -> list[Packet]:
    """One TCP segment that carries an application payload."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=9000, flags="PA")
        / Raw(load=b"hello tcp payload")
    ]


def udp() -> list[Packet]:
    """One UDP datagram that carries an application payload."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / UDP(sport=40000, dport=9001)
        / Raw(load=b"hello udp payload")
    ]


def http_get() -> list[Packet]:
    """An HTTP/1.1 GET request."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(
            load=(
                b"GET /index.html HTTP/1.1\r\n"
                b"Host: example.test\r\n"
                b"User-Agent: idstest/1.0\r\n"
                b"\r\n"
            )
        )
    ]


def http_post() -> list[Packet]:
    """An HTTP/1.1 POST request with a body."""
    body = b"username=alice&password=secret"
    header = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
    )
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(load=header + body)
    ]


def http_response() -> list[Packet]:
    """An HTTP/1.1 response with a status code and headers."""
    body = b"<html>ok</html>"
    header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: ids-test\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
    )
    return [
        _eth()
        / IP(src=DST, dst=SRC)
        / TCP(sport=80, dport=40000, flags="PA")
        / Raw(load=header + body)
    ]


def dns_query() -> list[Packet]:
    """A DNS query for an A record."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / UDP(sport=40000, dport=53)
        / DNS(id=4660, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    ]


def dns_response() -> list[Packet]:
    """A DNS response that carries at least one answer."""
    return [
        _eth()
        / IP(src=DST, dst=SRC)
        / UDP(sport=53, dport=40000)
        / DNS(
            id=4660,
            qr=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                ttl=300,
                rdata="93.184.216.34",
            ),
        )
    ]


def smtp_command() -> list[Packet]:
    """EHLO, MAIL FROM and RCPT TO commands."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=25, flags="PA")
        / Raw(load=b"EHLO mail.example.test\r\n"),
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=25, flags="PA")
        / Raw(load=b"MAIL FROM:<alice@example.test>\r\n"),
        _eth()
        / IP(src=SRC, dst=DST)
        / TCP(sport=40000, dport=25, flags="PA")
        / Raw(load=b"RCPT TO:<bob@example.test>\r\n"),
    ]


def smtp_response() -> list[Packet]:
    """An SMTP response line with a status code."""
    return [
        _eth()
        / IP(src=DST, dst=SRC)
        / TCP(sport=25, dport=40000, flags="PA")
        / Raw(load=b"250 2.1.0 Ok\r\n")
    ]


def unknown_protocol() -> list[Packet]:
    """A binary payload that belongs to no supported application protocol."""
    return [
        _eth()
        / IP(src=SRC, dst=DST)
        / UDP(sport=40000, dport=40001)
        / Raw(load=bytes(range(32)))
    ]


def malformed_packet() -> list[Packet]:
    """An IPv4 packet whose header length field is below the legal minimum."""
    raw = bytearray(
        bytes(
            IP(src=SRC, dst=DST)
            / UDP(sport=40000, dport=40001)
            / Raw(load=b"\x00" * 8)
        )
    )
    raw[0] = 0x43  # version 4 with a 12-byte header, which is not allowed
    return [_eth() / IP(bytes(raw))]


CASES: tuple[tuple[str, Callable[[], list[Packet]]], ...] = (
    ("tcp_handshake", tcp_handshake),
    ("tcp_data", tcp_data),
    ("udp", udp),
    ("http_get", http_get),
    ("http_post", http_post),
    ("http_response", http_response),
    ("dns_query", dns_query),
    ("dns_response", dns_response),
    ("smtp_command", smtp_command),
    ("smtp_response", smtp_response),
    ("unknown_protocol", unknown_protocol),
    ("malformed_packet", malformed_packet),
)


def cases() -> tuple[tuple[str, Callable[[], list[Packet]]], ...]:
    """Return the mandatory test cases in the order of the assignment table."""
    return CASES
