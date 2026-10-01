# Test cases — Decoder, Preprocessor & Flow/Connection Tracker

Every case below is an automated test. Each test has its own recorded run in
`results/`. Cases run through the real command line entry point are marked
*PCAP*; the others call the module function directly with a small dictionary.

## How to run

```bash
# all tests
python -m unittest discover -s TEST -v

# one case
python -m unittest TEST.test_decoder.DecoderTests.test_T01_url_decoding -v
```

## Mandatory cases

| # | Content | Input | Test method | Observed result | Evidence |
|---|---|---|---|---|---|
| T01 | HTTP URL decode | URI and form body with percent-encoding (`%27%20OR%201%3D1`, `a+b`, `%2527`) | `test_decoder.py::test_T01_url_decoding` | `decoded_http_target` = `/?q=' OR 1=1`, `+` becomes a space only in form data, `%2527` stays single-decoded, raw `http_target` unchanged | `results/T01.txt` |
| T02 | HTML entity | `&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;` in `text/html` | `test_decoder.py::test_T02_html_entities` | `decoded_body` = `<script>alert("x")</script> & '`, JSON body untouched, no crash | `results/T02.txt` |
| T03 | SMTP Base64/QP | Base64 `SGVsbG8=`, quoted-printable `Xin ch=C3=A0o`, multipart, and a full `DATA` message | `test_decoder.py::test_T03_mime_base64_and_qp` | `decoded_body` = `Hello` / `Xin chào`, `decode_status` = `OK`, two `mime_parts`, no header means `SKIPPED` | `results/T03.txt` |
| T04 | Invalid bytes | Non-UTF-8 body, bad ASCII, broken Base64/QP, `%FF` | `test_decoder.py::test_T04_invalid_bytes_continue` | `decode_status` = `PARTIAL` with a reason, valid packet after it still decodes as `OK` | `results/T04.txt` |
| T05 | Normalization | Mixed-case protocol/header/domain, `+07:00` timestamp, ports as text | `test_preprocessor.py::test_T05_normalization` | `TCP`/`HTTP`/`IPv4`, host `example.test`, domain `example.com`, timestamp in UTC, path case kept | `results/T05.txt` |
| T06 | Missing field | Event without optional fields, and with explicit `null` lists | `test_preprocessor.py::test_T06_missing_optional_fields` | `null` for scalars, `[]` for lists, `{}` for headers, `partial`, no exception | `results/T06.txt` |
| T07 | TCP handshake | SYN → SYN/ACK → ACK (no payload) *PCAP too* | `test_flow_tracker.py::test_T07_tcp_handshake` | 1 flow, `HANDSHAKE → HANDSHAKE → ESTABLISHED`, 3 packets, `SYN_count` 2, `ACK_count` 2 | `results/T07.txt` |
| T08 | Bidirectional flow | A→B, B→A, A→B with the reversed 5-tuple | `test_flow_tracker.py::test_T08_bidirectional_flow` | Same `flow_id`, `forward`/`backward`/`forward`, 2/1 packet split, 1 active flow | `results/T08.txt` |
| T09 | TCP close | FIN/ACK both ways, then ACK; later a RST flow | `test_flow_tracker.py::test_T09_tcp_close_and_reset` | `CLOSING` while only one FIN is seen, `CLOSED` (`tcp_fin`) after both, `RESET` (`tcp_rst`) for RST, flow leaves the table | `results/T09.txt` |
| T10 | UDP query/response | DNS query and reversed DNS response with real packets | `test_flow_tracker.py::test_T10_udp_dns_query_response` | 1 UDP flow, `application_protocol` `DNS`, `ACTIVE`, 2 packets, byte counts match `len(bytes(packet))`, `duration` 1 | `results/T10.txt` |
| T11 | Concurrent flows | Four flows differing in port, address, or protocol | `test_flow_tracker.py::test_T11_concurrent_flows` | Four different `flow_id`s, no wrong merging, reversed packet joins the right one | `results/T11.txt` |
| T12 | Idle timeout | TCP timeout 10s, UDP timeout 5s, fixed timestamps | `test_flow_tracker.py::test_T12_idle_timeout_and_cleanup` | Each flow is exported once as `CLOSED`/`idle_timeout` and removed; `finish_flows` exports the rest as `eof` | `results/T12.txt` |
| T13 | Statistics | 6 TCP packets, both directions, out-of-order timestamps | `test_flow_tracker.py::test_T13_statistics` | `packet_count` 6, `byte_count` 381, 4/2 and 265/116 by direction, flag counts 2/5/0/0, `duration` 3 | `results/T13.txt` |
| T14 | Malformed event | `None`, `[]`, `{}`, bad IP, port 65536, `True` port, huge port string, bad timestamp, `NaN`, ICMP, negative length, non-JSON value | `test_preprocessor.py::test_T14_malformed_and_unsupported` | `invalid` with `reason`, `mark`/`skip` policy applied, not trackable, output still JSON-safe | `results/T14.txt` |

## End-to-end runs through the command line

| Test method | Scenario | Observed result | Evidence |
|---|---|---|---|
| `test_main.py::RunnerTests.test_parser_reuse_smoke` | Homework 1 parser reused for one HTTP packet | Same event fields, `packet_length` added, PCAP run exits 0 | `results/smoke.txt` |
| `test_main.py::RunnerTests.test_end_to_end_http_tcp` | 9-packet HTTP session: handshake, POST with form body, HTML response, FIN close | One flow, `ESTABLISHED` on packet 3, URL/form/HTML decoded, flow `CLOSED` with `tcp_fin`, byte count equals the sum of captured packet lengths | `results/integration_http_tcp.txt` |
| `test_main.py::RunnerTests.test_bad_bytes_then_mime_pcap` | Bad-byte HTTP packet, then Base64 and Quoted-Printable SMTP packets; also `--max-decode-size 16` | Bad packet stays `PARTIAL` and the next packets still decode; two flows, both exported at `eof`; size limit reports `PARTIAL` without crashing | `results/integration_mime_bytes.txt` |
| `test_main.py::RunnerTests.test_bad_packet_policy_and_unreadable_input` | Malformed IPv4 packet with `mark` and `skip`, cut PCAP trailer, invalid CLI options | Invalid event marked or skipped (the next packet keeps its own `packet_id`), cut record reported as `INCOMPLETE` and the readable flow still exported, bad options exit 2 | `results/integration_policy.txt` |

## Notes

- Byte counts use the captured packet length (`len(bytes(packet))`), including
  headers, never the length of decoded text.
- Flow tests use fixed timestamps, so no test waits for a real timeout.
- Extra decoder checks (form pairs, size limit, multipart, single decode) are
  inside the cases above instead of being separate letters.
