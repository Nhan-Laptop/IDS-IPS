# Test cases — Packet Capture & Parser

Every numbered requirement of the assignment is covered by an automated test and
by recorded evidence committed in this folder.

## How to reproduce

```bash
# full automated suite
python -m unittest discover -s TEST -v

# regenerate the section 9 captures, logs and summary
python TEST/make_test_pcaps.py
```

## Section 9 — mandatory test cases

Each case is executed through the real command line entry point
(`python main.py --pcap TEST/pcap/<case>.pcap --output TEST/output/<case>.jsonl`),
so it covers PCAP import, the shared parsing pipeline, the normalized event and
the JSON Lines log.

| # | Test | Requirement | Capture | Test method | Observed result |
|---|---|---|---|---|---|
| 1 | TCP handshake | Recognize SYN, SYN/ACK, ACK | `pcap/tcp_handshake.pcap` | `test_mandatory_cases.test_tcp_handshake` | `["SYN"]`, `["SYN","ACK"]`, `["ACK"]`, `parse_status` `OK` |
| 2 | TCP data | Parse a TCP packet with payload | `pcap/tcp_data.pcap` | `test_mandatory_cases.test_tcp_data` | `transport_protocol` `TCP`, ports `40000 → 9000`, `payload_length` `17` |
| 3 | UDP | Parse a UDP packet | `pcap/udp.pcap` | `test_mandatory_cases.test_udp` | `transport_protocol` `UDP`, ports `40000 → 9001`, `payload_length` `17` |
| 4 | HTTP GET | Parse an HTTP request | `pcap/http_get.pcap` | `test_mandatory_cases.test_http_get` | `http_method` `GET`, `http_target` `/index.html`, `http_version` `HTTP/1.1`, `headers.host` `example.test` |
| 5 | HTTP POST | Parse an HTTP request with body | `pcap/http_post.pcap` | `test_mandatory_cases.test_http_post` | `http_method` `POST`, `http_target` `/login`, `body` `username=alice&password=secret`, `headers.content-length` `30` |
| 6 | HTTP response | Parse status code and header | `pcap/http_response.pcap` | `test_mandatory_cases.test_http_response` | `http_message_type` `response`, `status_code` `200`, `reason_phrase` `OK`, `headers.server` `ids-test` |
| 7 | DNS query | Parse domain and query type | `pcap/dns_query.pcap` | `test_mandatory_cases.test_dns_query` | `dns_is_response` `false`, `dns_questions` `[{"name": "example.com", "type": "A"}]` |
| 8 | DNS response | Parse at least one answer | `pcap/dns_response.pcap` | `test_mandatory_cases.test_dns_response` | `dns_is_response` `true`, `dns_answers` `[{"name": "example.com", "type": "A", "ttl": 300, "data": "93.184.216.34"}]` |
| 9 | SMTP command | Parse HELO/EHLO, MAIL FROM or RCPT TO | `pcap/smtp_command.pcap` | `test_mandatory_cases.test_smtp_command` | `smtp_command` `EHLO` `mail.example.test`, `MAIL FROM` `<alice@example.test>`, `RCPT TO` `<bob@example.test>` |
| 10 | SMTP response | Parse SMTP status code | `pcap/smtp_response.pcap` | `test_mandatory_cases.test_smtp_response` | `smtp_message_type` `response`, `smtp_status_code` `250`, `smtp_text` `2.1.0 Ok` |
| 11 | Unknown protocol | Must not crash | `pcap/unknown_protocol.pcap` | `test_mandatory_cases.test_unknown_protocol_does_not_crash` | `application_protocol` `UNKNOWN`, `parse_status` `OK`, process exit code `0` |
| 12 | Malformed packet | Must not crash | `pcap/malformed_packet.pcap` | `test_mandatory_cases.test_malformed_packet_does_not_crash` | `parse_status` `MALFORMED`, `error` `invalid IPv4 header length`, process exit code `0` |

Recorded evidence: `output/<case>.jsonl` holds the JSON Lines log of each case,
`output/summary.txt` holds the same results in text form, and
`mandatory_cases_results.txt` holds the recorded test run.

## Additional requirement coverage

| Requirement | Where it is tested |
|---|---|
| §2.1.1 Live capture interface selection, count, timeout, filter | `test_capture_cli.py` |
| §2.1.2 PCAP import through the same pipeline | `test_capture_cli.py`, `test_mandatory_cases.py` |
| §3 Pipeline: IPv4 → TCP/UDP → application → event | `test_pipeline.py` |
| §4 Non-standard port detection (HTTP, DNS over UDP/TCP, SMTP) | `test_nonstandard_ports.py` |
| §5 Unknown protocol handling (`mark` / `skip`) | `test_unknown_policy.py` |
| §6 Normalized JSON-compatible event structure | `test_event_schema.py` |
| §7 Error handling for malformed, unsupported, missing header, empty payload, truncated PCAP, undecodable payload | `test_error_handling.py` |
| §8 JSON Lines result log, including error events | `test_jsonl_log.py` |

## Files in this folder

```text
TESTCASES.md                  this document
mandatory_cases.py            packet builders for the section 9 cases
make_test_pcaps.py            regenerates pcap/, output/ and summary.txt
test_mandatory_cases.py       section 9 automated tests
test_capture_cli.py           capture and CLI tests
test_pipeline.py              protocol parser tests
test_nonstandard_ports.py     section 4 tests
test_unknown_policy.py        section 5 tests
test_event_schema.py          section 6 tests
test_error_handling.py        section 7 tests
test_jsonl_log.py             section 8 tests
pcap/                         generated captures for the section 9 cases
output/                       recorded JSON Lines logs and summary
*_results.txt                 recorded test runs
```
