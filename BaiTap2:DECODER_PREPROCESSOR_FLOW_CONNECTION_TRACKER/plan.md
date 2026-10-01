# Homework 2 — Simple Plan

## Approach

Keep Homework 1 unchanged. Reuse its parser and add just three small modules.
Use plain Python functions, a dictionary for flows, and `unittest`.

```text
Homework 1 parser → decoder → preprocessor → flow tracker
```

No extra framework, separate configuration package, TLS decryption, or full
TCP stream reassembly. We are meeting the assignment, not building a complete IDS.

## Files

```text
main.py                 Read PCAP, call the modules, save JSONL output
decoder.py              Decode HTTP and SMTP/MIME data
preprocessor.py         Check and normalize events
flow_tracker.py         Track flows, states, and statistics
TEST/                   Automated tests and results for T01–T14
README.md               Run instructions and AI-use disclosure
```

## Required features

### Decoder
- Decode HTTP percent escapes, form data, and HTML entities in suitable text.
  Handle `+` as a space in form data, not everywhere in a URI.
- Decode MIME Base64/Quoted-Printable when the headers specify the encoding.
- Support ASCII/UTF-8. Bad bytes produce a decode status/reason, not a crash.
- Keep original fields; add decoded fields separately. Decode once.
- The runner passes original payload bytes when needed, because Homework 1's
  text output cannot recover bytes already replaced during UTF-8 decoding.

### Preprocessor
- Check required fields, IP addresses, port ranges, timestamps, and protocols.
- Normalize protocols, IP/domain values, header names, timestamps, and URI/path
  safely. Do not lowercase paths or change their meaning.
- Use `null` for missing scalar fields, `[]` for lists, and `{}` for headers.
- Add `preprocess_status` (`valid/partial/invalid`), `processing_action`, and
  `reason` when needed. Mark or skip bad events without stopping the program.

### Flow tracker
- Match a 5-tuple and its reverse to one flow. Use IDs like `flow_1`.
- First sender = endpoint A; A → B = forward, B → A = backward.
- Keep empty TCP packets and packets whose application protocol is `UNKNOWN`.
- Follow SYN/ACK for the handshake, FINs in both directions for closure, and
  RST for reset: `NEW/HANDSHAKE → ESTABLISHED → CLOSING → CLOSED/RESET`.
- Group UDP packets by the same bidirectional tuple.
- Store endpoints, transport/application protocols, start/last-seen times,
  duration, total/directional packet and byte counts, TCP flag counts, and state.
- Use captured packet length from the runner for byte counts.
- Expire idle TCP/UDP flows using packet timestamps; save and remove them.
  A later connection gets a new ID. Save remaining flows at EOF too.
- Do not create flows from invalid addresses, ports, or timestamps.

Keep settings in the runner: configurable TCP/UDP timeouts, maximum decode size,
and mark/skip policy. Save enriched events and flow summaries in two JSONL files.

## Step-by-step order

| Step | Small task | Tests |
|---|---|---|
| 1 | Basic runner, parser reuse, and settings | Smoke test |
| 2 | HTTP URL/form and HTML decoding | T01, T02 |
| 3 | MIME decoding and bad-byte handling | T03, T04 |
| 4 | Validation, normalization, missing/bad fields | T05, T06, T14 |
| 5 | Bidirectional flows, UDP, separate flows | T08, T10, T11 |
| 6 | TCP handshake and closure/reset | T07, T09 |
| 7 | Statistics and idle timeout | T13, T12 |
| 8 | Finish output, README, and regression checks | All tests |

For each small task: explain it simply, implement it, test it, then commit it.
Run and commit each required test case separately, with its result under `TEST/`.
Use fixed timestamps in tests instead of waiting for real timeouts.

Finished means T01–T14 pass, Homework 1's 79 tests still pass, README documents
the byte-count choice and AI assistance, and you can explain the code.
