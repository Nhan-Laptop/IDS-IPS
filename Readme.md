# IDS-IPS: Packet Capture & Parser

This repository currently implements the first phase of **Assignment 1 – Packet Capture & Parser for an IDS**.

## Implemented in this phase

The current code covers:

- **§2.1.1 Live Capture** from a selected network interface.
- **§2.1.2 PCAP Import** from a `.pcap` file.
- **§3 Packet Parsing and Processing Pipeline**.

Both capture modes use the same packet callback and the same parser. There are not separate parsers for live traffic and PCAP input.

## Architecture

```text
Live interface / PCAP file
            |
            v
       Raw Scapy Packet
            |
            v
       IPv4 network parser
            |
            v
       TCP / UDP parser
            |
            v
  Application protocol detector
            |
            v
 HTTP / DNS / SMTP parser
            |
            v
   Normalized IDS JSON event
```

The shared entry point is `parsers.parse_packet(packet, packet_id)`.

## Capture functions

### Live capture

`Capture_through_interface()` uses Scapy and supports:

- Interface selection with `iface`.
- Packet limit with `count` (`0` means unlimited).
- Capture timeout.
- Optional BPF filter.
- Immediate callback invocation for every packet.
- Capture timestamps from Scapy's `packet.time`.

Example:

```bash
sudo python main.py --interface eth0
```

Useful options:

```bash
sudo python main.py \
  --interface eth0 \
  --count 10 \
  --timeout 30 \
  --filter "tcp or udp"
```

The interface name depends on the operating system. Suitable permissions are required for live capture.

### PCAP import

`Capture_through_pcap()` reads a PCAP file and sends each packet through the same callback and parser used for live capture:

```bash
python main.py --pcap test.pcap
```

Limit the number of imported packets:

```bash
python main.py --pcap test.pcap --count 20
```

## Parsing support

### Network and transport layers

- IPv4 source and destination addresses.
- TCP source and destination ports.
- TCP flags, including `SYN`, `SYN/ACK`, and `ACK`.
- TCP sequence number, acknowledgment number, and window size.
- UDP source and destination ports.
- Transport payload length.

### Application protocols

The detector combines payload signatures with conventional ports. It does not depend entirely on the port number.

- **HTTP/1.x**
  - Request methods such as `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, and `OPTIONS`.
  - Request target and HTTP version.
  - Response status code and reason phrase.
  - Headers and request/response body.
  - Payload-based detection on non-standard ports.
- **DNS**
  - Transaction ID and query/response flag.
  - Query domain and query type.
  - DNS answer name, type, TTL, and data.
  - Payload-based detection when DNS uses a non-standard port.
- **SMTP**
  - `HELO`, `EHLO`, `MAIL FROM`, and `RCPT TO` commands.
  - SMTP response status code and response text.

Unknown application protocols are represented as `"UNKNOWN"` and do not stop capture.

### Non-standard ports (§4)

Port numbers are hints, never the only evidence:

- HTTP requests and responses are recognized from their start line, so
  `PUT /upload HTTP/1.0` is parsed on port 18080 as well.
- SMTP commands and status lines are recognized from their payload shape on
  any port.
- DNS is parsed from a structurally valid message, including DNS over TCP
  with its two-byte length prefix. The header counts must match the decoded
  records, which keeps binary false positives out.
- Conventional ports (`80`, `8080`, `25`, `53`, `5300`, `5353`) are used as
  a secondary hint, mainly so that broken DNS traffic on port 53 is still
  reported as DNS with `parse_status` `MALFORMED` instead of `UNKNOWN`.

### Unknown application policy (§5)

Packets whose application protocol cannot be identified are handled by
configuration:

- `--unknown-policy mark` (default) writes the packet as an event with
  `"application_protocol": "UNKNOWN"` so later IDS stages can still score it.
- `--unknown-policy skip` drops those events. Packet ids still follow the
  captured packet order, so a gap in `packet_id` marks a skipped packet.

```bash
python main.py --pcap test.pcap --unknown-policy skip
```

## Normalized JSON Lines output

Each packet produces one JSON object on one line. By default, events are printed to standard output:

```bash
python main.py --pcap test.pcap
```

Events can be written to a JSON Lines file with `--output`:

```bash
python main.py --pcap test.pcap --output events.jsonl
```

A normalized event contains common fields such as:

```json
{
  "packet_id": 1,
  "timestamp": "2023-11-14T22:13:20.125000+00:00",
  "src_ip": "10.0.0.1",
  "dst_ip": "10.0.0.2",
  "network_protocol": "IPv4",
  "transport_protocol": "TCP",
  "src_port": 40000,
  "dst_port": 18080,
  "application_protocol": "HTTP",
  "payload_length": 37,
  "parse_status": "OK"
}
```

Protocol-specific fields are added when available, for example `http_method`, `headers`, `dns_questions`, `dns_answers`, or `smtp_status_code`.

### Normalized event schema (§6)

`parsers/schema.py` defines the output contract and `parsers.validate_event(event)`
returns the schema problems of one event, where an empty list means valid.
Every event always contains the same common fields:

| Field | Type | Meaning |
|---|---|---|
| `packet_id` | integer | 1-based captured packet order |
| `timestamp` | string / null | ISO-8601 UTC capture time |
| `src_ip`, `dst_ip` | string / null | IPv4 addresses |
| `network_protocol` | string | `IPv4` or `UNKNOWN` |
| `transport_protocol` | string | `TCP`, `UDP`, or `UNKNOWN` |
| `src_port`, `dst_port` | integer / null | Ports when a transport header exists |
| `tcp_flags` | list of strings | `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `ECE`, `CWR` |
| `tcp_sequence`, `tcp_acknowledgment`, `tcp_window` | integer / null | TCP header values |
| `application_protocol` | string | `HTTP`, `DNS`, `SMTP`, or `UNKNOWN` |
| `payload_length` | integer | Transport payload size in bytes |
| `parse_status` | string | `OK`, `UNSUPPORTED`, `INCOMPLETE`, or `MALFORMED` |
| `error` | string | Present only when parsing could not complete |

Protocol parsers only add their documented optional fields (`http_*`,
`status_code`, `headers`, `body`, `dns_*`, `smtp_*`). Raw packet bytes and
Scapy objects are never placed into an event, which is what allows the later
detection engine to work without touching raw packets.

## Error handling

Malformed, truncated, unsupported, or incomplete packets are converted into an event instead of crashing the capture loop. The event can contain one of these statuses:

- `OK` — packet parsed successfully.
- `UNKNOWN` — reserved for unsupported application identification in the normalized event.
- `UNSUPPORTED` — network or transport protocol is outside the supported scope.
- `INCOMPLETE` — the captured packet does not contain enough bytes for the expected header or payload.
- `MALFORMED` — a header or application payload could not be decoded safely.

The event includes an `error` field when parsing cannot be completed.

## Project structure

```text
main.py                    Capture functions, CLI, and shared output callback
parsers/
  __init__.py              Public parser entry point
  errors.py                Parser error types
  pipeline.py              IPv4 -> TCP/UDP -> application -> event pipeline
  schema.py                Normalized event schema and validator
TEST/
  test_capture_cli.py      Capture, CLI, JSONL, and PCAP tests
  test_pipeline.py         Required protocol and error-handling tests
  test_nonstandard_ports.py  Non-standard port detection tests
  test_unknown_policy.py   Unknown protocol mark/skip tests
  test_event_schema.py     Normalized output structure tests
  capture_cli_results.txt  Capture test output
  pipeline_results.txt     Parser test output
  nonstandard_ports_results.txt  Non-standard port test output
  unknown_policy_results.txt     Unknown policy test output
  event_schema_results.txt       Schema test output
docs/
  Bai-tap-01_Packet_Capture_Parser_IDS.pdf
```

## Installation and testing

Install the runtime dependency:

```bash
python -m pip install scapy
```

Run the full test suite:

```bash
python -m unittest discover -s TEST -v
```

The current suite covers:

- TCP handshake: `SYN`, `SYN/ACK`, `ACK`.
- TCP data and UDP packets.
- HTTP GET, POST, and response packets.
- DNS query and response packets.
- SMTP commands and responses.
- Unknown protocol, unsupported packet, and malformed packet handling.
- Shared live/PCAP callback wiring and JSON Lines output.
- Non-standard port detection for HTTP, DNS over UDP/TCP, and SMTP.
- Unknown protocol mark/skip configuration.
- Normalized event schema validation for HTTP, DNS, SMTP, unknown, unsupported, and malformed packets.

## Current scope and next steps

This phase parses packets independently. TCP stream reassembly, IP fragmentation reassembly, and the later IDS detection engine are not implemented yet. The next phases can consume the normalized JSON events without accessing Scapy raw packets directly.

## AI assistance disclosure

AI tool used: **OpenAI ChatGPT through the pi coding agent**.

Purpose of use:

- Discuss the implementation design.
- Assist with Scapy capture and parser code.
- Suggest test cases and documentation structure.

The submitted code should be reviewed, tested, and understood by the student before submission. AI assistance does not replace the student's responsibility to explain the implementation.
