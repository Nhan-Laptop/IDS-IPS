"""Build small PCAPs and run the real command line on them as saved evidence."""

import json
from pathlib import Path
import subprocess
import sys

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
PCAP_DIR = HERE / "pcap"
OUTPUT_DIR = HERE / "output"
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(HERE))

from test_main import tcp_packet  # noqa: E402


def http_request():
    form = b"name=Alice+Smith&literal=%2B"
    request = (b"POST /Search?q=%27%20OR%201%3D1 HTTP/1.1\r\nHost: EXAMPLE.TEST\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\n"
               + f"Content-Length: {len(form)}\r\n\r\n".encode() + form)
    body = b"&lt;script&gt;x&lt;/script&gt;"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    base = 1700000000
    return [tcp_packet("S", base),
            tcp_packet("SA", base + 1, True, seq=500, ack=101),
            tcp_packet("A", base + 2, seq=101, ack=501),
            tcp_packet("PA", base + 3, payload=request, seq=101, ack=501),
            tcp_packet("PA", base + 4, True, response, seq=501, ack=101 + len(request)),
            tcp_packet("FA", base + 5, seq=101 + len(request), ack=501 + len(response)),
            tcp_packet("A", base + 6, True, seq=501 + len(response), ack=102 + len(request)),
            tcp_packet("FA", base + 7, True, seq=501 + len(response), ack=102 + len(request)),
            tcp_packet("A", base + 8, seq=102 + len(request), ack=502 + len(response))]


def smtp_mime():
    base = 1700000000
    packets = []
    for offset, payload in enumerate([
            b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=",
            b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n\r\nXin ch=C3=A0o"]):
        packet = tcp_packet("PA", base + offset, payload=payload)
        packet[TCP].sport, packet[TCP].dport = 40001, 25
        packets.append(packet)
    return packets


def udp_dns():
    query = (IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=53)
             / DNS(id=123, qd=DNSQR(qname="EXAMPLE.COM.")))
    response = (IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=40000)
                / DNS(id=123, qr=1, qd=DNSQR(qname="EXAMPLE.COM."),
                      an=DNSRR(rrname="EXAMPLE.COM.", type="A", rdata="93.184.216.34")))
    query.time, response.time = 1700000000, 1700000001
    return [query, response]


def bad_then_mime():
    bad = tcp_packet("PA", 1700000000, payload=(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ninvalid: \xff"))
    return [bad, *smtp_mime()]


def concurrent_flows():
    base = 1700000000
    other = tcp_packet("PA", base + 1, payload=b"GET /other HTTP/1.1\r\nHost: b.test\r\n\r\n")
    other[IP].dst = "10.0.0.3"
    return [tcp_packet("S", base),
            tcp_packet("SA", base + 1, True, seq=500, ack=101),
            tcp_packet("A", base + 2, seq=101, ack=501),
            tcp_packet("PA", base + 2, payload=b"GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n",
                       seq=101, ack=501),
            other]


CASES = {
    "http_request": (http_request, ()),
    "smtp_mime": (smtp_mime, ()),
    "udp_dns": (udp_dns, ("--udp-timeout", "30")),
    "bad_then_mime": (bad_then_mime, ()),
    "concurrent_flows": (concurrent_flows, ("--tcp-timeout", "1")),
}


def run_case(name, builder, options):
    packets = builder()
    pcap = PCAP_DIR / f"{name}.pcap"
    events = OUTPUT_DIR / f"{name}_events.jsonl"
    flows = OUTPUT_DIR / f"{name}_flows.jsonl"
    wrpcap(str(pcap), packets)
    command = [sys.executable, "-B", str(PROJECT / "main.py"), "--pcap", str(pcap),
               "--output", str(events), "--flows-output", str(flows), *options]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise SystemExit(f"{name} failed: {result.stderr}")
    event_lines = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines()]
    flow_lines = [json.loads(line) for line in flows.read_text(encoding="utf-8").splitlines()]
    return event_lines, flow_lines


def main():
    PCAP_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)
    summary = ["Homework 2 evidence", ""]
    for name, (builder, options) in CASES.items():
        events, flows = run_case(name, builder, options)
        summary.append(f"{name}: {len(events)} events, {len(flows)} flows")
        for flow in flows:
            summary.append(
                f"  {flow['flow_id']} {flow['protocol']}/{flow['application_protocol']} "
                f"{flow['state']} packets={flow['packet_count']} bytes={flow['byte_count']} "
                f"reason={flow['close_reason']}")
        for event in events:
            if event.get("decode_status") in ("PARTIAL", "ERROR") or event["preprocess_status"] == "invalid":
                summary.append(f"  packet {event['packet_id']}: "
                               f"decode={event['decode_status']} preprocess={event['preprocess_status']} "
                               f"reason={event['decode_reason'] or event['reason']}")
        summary.append("")
    text = "\n".join(summary).rstrip() + "\n"
    (OUTPUT_DIR / "summary.txt").write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
