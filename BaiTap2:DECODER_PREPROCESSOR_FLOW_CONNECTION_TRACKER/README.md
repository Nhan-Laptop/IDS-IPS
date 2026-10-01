# NT204.R11.ANTN — IDS/IPS: Decoder, Preprocessor & Flow/Connection Tracker

| | |
|---|---|
| Course | NT204 — Hệ thống tìm kiếm, phát hiện và ngăn ngừa xâm nhập (IDS/IPS) |
| Class code (mã lớp) | NT204.R11.ANTN |
| Student (họ & tên) | Nguyễn Trọng Nhân |
| Student ID (MSSV) | 24521236 |
| Repository | <https://github.com/Nhan-Laptop/NT204.R11.ANTN_Nguyen-Trong-Nhan_24521236> |

This is the second phase of the assignment. It takes the events produced by
Homework 1 (Packet Capture & Parser) and adds three small modules:

```text
Homework 1 parser → decoder → preprocessor → flow tracker
```

Homework 1 is not modified. Its `parse_packet()` is reused, so this phase only
reads a PCAP file and then decodes, checks and groups the resulting events.

The plan followed here is in `plan.md`.

## Files

```text
main.py            Read the PCAP, call the modules, write the two JSONL files
decoder.py         Decode HTTP text and SMTP/MIME bodies
preprocessor.py    Validate and normalize one event
flow_tracker.py    Group events into flows, keep states and statistics
plan.md            The simple plan for this phase
TEST/              Tests, per-case evidence and the case mapping document
docs/              Assignment PDF
```

## How to run

Scapy from Homework 1 is the only dependency:

```bash
python -m pip install scapy
python main.py --pcap test.pcap
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `--pcap` | required | Input capture file |
| `--output` | `events.jsonl` | One enriched event per line |
| `--flows-output` | `flows.jsonl` | One flow summary per completed flow |
| `--tcp-timeout` | `120` | Idle seconds before a TCP flow expires |
| `--udp-timeout` | `30` | Idle seconds before a UDP flow expires |
| `--max-decode-size` | `65536` | Largest decoded value; larger input is truncated and marked `PARTIAL` |
| `--invalid-policy` | `mark` | `mark` writes an invalid event, `skip` drops it |

Example with short timeouts:

```bash
python main.py --pcap test.pcap --output events.jsonl --flows-output flows.jsonl \
  --tcp-timeout 60 --udp-timeout 15 --invalid-policy mark
```

## What each module does

### Decoder

Keeps the original fields and adds decoded ones, so the raw representation is
never lost:

- HTTP `http_target` → `decoded_http_target` (percent decoding).
- HTTP `body` → `decoded_body` (HTML entities for text types, decoded body for
  form data) and `decoded_form` (name/value pairs).
- MIME text parts → `mime_parts` with a `decoded_body` per part; Base64 and
  Quoted-Printable are used only when `Content-Transfer-Encoding` says so.
- `decode_status` is `OK`, `PARTIAL`, `SKIPPED` or `ERROR`, with `decode_reason`
  explaining a problem. Invalid bytes never stop the run.
- Decoding happens once. `%2527` stays `%27` and `+` becomes a space only in
  form data, not in a URI path.

### Preprocessor

- Checks required fields, IP addresses, port ranges, timestamps, transport and
  application protocol names.
- Normalizes protocol names, IP addresses, HTTP header names, domain names and
  timestamps to UTC. Path case is kept and the URI meaning is not rewritten.
- Missing values are consistent: `null` for scalars, `[]` for lists, `{}` for
  headers.
- Adds `preprocess_status` (`valid`/`partial`/`invalid`), `processing_action`
  (`keep`/`mark`/`skip`), `trackable` and `reason`.
- An invalid event can still be written, but it never creates a flow, and the
  next packet is processed normally.

### Flow tracker

- A flow is a bidirectional 5-tuple (src IP, dst IP, src port, dst port,
  protocol); the reversed tuple joins the same flow.
- The first sender becomes endpoint A, so A → B is `forward` and B → A is
  `backward`.
- TCP states: `NEW → HANDSHAKE → ESTABLISHED → CLOSING → CLOSED`, or `RESET`.
  A SYN/ACK must come from the other side and a bare ACK is not enough to
  establish a flow, so payload-free TCP packets can be tracked safely.
- UDP has no handshake, so its state is `ACTIVE` and packets are grouped by the
  same bidirectional tuple.
- Each flow keeps `flow_id`, protocol, application protocol, endpoints,
  `start_time`, `last_seen`, `duration`, total and per-direction packet and byte
  counts, TCP flag counts and `state`.
- Idle flows expire using packet timestamps (capture time, not reading speed)
  and are written as `CLOSED` with `close_reason` `idle_timeout`. Flows still
  active when the file ends are written with `close_reason` `eof`; their `state`
  stays what the captured packets showed, for example `ESTABLISHED` or `ACTIVE`.

### Byte count choice

`byte_count`, `forward_byte_count` and `backward_byte_count` use the captured
packet length (`len(bytes(packet))`), including the Ethernet/IP/TCP headers.
That is the value the runner supplies, and the tests use the same definition.

## Output

`events.jsonl` — the Homework 1 event plus decode, preprocess and flow fields:

```json
{
  "packet_id": 4,
  "timestamp": "2023-11-14T22:13:23+00:00",
  "src_ip": "10.0.0.1",
  "dst_ip": "10.0.0.2",
  "src_port": 40000,
  "dst_port": 80,
  "application_protocol": "HTTP",
  "http_target": "/Search?q=%27%20OR%201%3D1",
  "body": "name=Alice+Smith&literal=%2B",
  "packet_length": 215,
  "decoded_http_target": "/Search?q=' OR 1=1",
  "decoded_body": "name=Alice Smith&literal=+",
  "decoded_form": [
    {"name": "name", "value": "Alice Smith"},
    {"name": "literal", "value": "+"}
  ],
  "decode_status": "OK",
  "preprocess_status": "valid",
  "processing_action": "keep",
  "flow_id": "flow_1",
  "direction": "forward",
  "flow_state": "ESTABLISHED",
  "track_status": "OK"
}
```

`flows.jsonl` — one summary per completed flow:

```json
{
  "flow_id": "flow_1",
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "endpoint_a": {"ip": "10.0.0.1", "port": 40000},
  "endpoint_b": {"ip": "10.0.0.2", "port": 80},
  "state": "CLOSED",
  "close_reason": "tcp_fin",
  "start_time": "2023-11-14T22:13:20+00:00",
  "last_seen": "2023-11-14T22:13:28+00:00",
  "duration": 8.0,
  "packet_count": 9,
  "byte_count": 756,
  "forward_packet_count": 5,
  "backward_packet_count": 4,
  "forward_byte_count": 431,
  "backward_byte_count": 325,
  "SYN_count": 2,
  "ACK_count": 8,
  "FIN_count": 2,
  "RST_count": 0
}
```

## Tests

```bash
python -m unittest discover -s TEST -v
```

All 14 mandatory cases T01–T14 are covered, plus end-to-end runs through the
command line. `TEST/TESTCASES.md` maps every case to its test method and
observed result, and `TEST/results/` keeps one saved run per case.

## Scope

There is no live capture in this phase, no TLS/DoH/DoT decryption and no TCP
stream reassembly. Only the three modules the assignment asks for are
implemented.

## AI assistance disclosure

AI tool used: **OpenAI ChatGPT through the pi coding agent**.

Purpose of use:

- Discuss the design of the three modules and the shape of the output.
- Suggest test cases for T01–T14 and help write them.
- Help write documentation.

I ran every test, read the results, and can explain the code myself. AI
assistance does not replace the student's responsibility for the submitted work.
