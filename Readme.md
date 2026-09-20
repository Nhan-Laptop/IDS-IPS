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
TEST/
  test_capture_cli.py      Capture, CLI, JSONL, and PCAP tests
  test_pipeline.py         Required protocol and error-handling tests
  capture_cli_results.txt  Capture test output
  pipeline_results.txt     Parser test output
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

## Current scope and next steps

This phase parses packets independently. TCP stream reassembly, IP fragmentation reassembly, and the later IDS detection engine are not implemented yet. The next phases can consume the normalized JSON events without accessing Scapy raw packets directly.

## AI assistance disclosure

AI tool used: **OpenAI ChatGPT through the pi coding agent**.

Purpose of use:

- Discuss the implementation design.
- Assist with Scapy capture and parser code.
- Suggest test cases and documentation structure.

The submitted code should be reviewed, tested, and understood by the student before submission. AI assistance does not replace the student's responsibility to explain the implementation.
