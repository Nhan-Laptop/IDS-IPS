# knowledge.md — Hiểu toàn bộ Bài tập 2 & code

> Tài liệu học tập cho **Bài tập 2: Decoder, Preprocessor & Flow/Connection Tracker** (NT204).
> Viết theo kiểu "dễ hiểu nhất có thể": khái niệm trước, rồi mới chỉ vào code.
> Mọi tên hàm, tên field và con số đều khớp với code thật trong repo này.
>
> **Cách học:** đọc mục 1–4 để nắm bức tranh, mở code đọc kèm mục 6.
> Mục 10 (cái bẫy) và mục 12 (câu hỏi vấn đáp) là phần quan trọng nhất khi bị hỏi.

---

## Mục lục

1. [Nắm bài trong 5 phút](#1-nắm-bài-trong-5-phút)
2. [Module này nằm ở đâu trong một IDS](#2-module-này-nằm-ở-đâu-trong-một-ids)
3. [Luồng dữ liệu chạy qua code](#3-luồng-dữ-liệu-chạy-qua-code)
4. [Bản đồ file trong repo](#4-bản-đồ-file-trong-repo)
5. [Kiến thức nền tảng](#5-kiến-thức-nền-tảng)
6. [Giải thích từng file / từng hàm](#6-giải-thích-từng-file--từng-hàm)
7. [Event và flow output gồm những gì](#7-event-và-flow-output-gồm-những-gì)
8. [Các trạng thái: decode / preprocess / track / flow](#8-các-trạng-thái)
9. [Bảng quyết định thiết kế](#9-bảng-quyết-định-thiết-kế)
10. [Cái bẫy thực tế đã gặp khi làm bài](#10-cái-bẫy-thực-tế-đã-gặp)
11. [Cheatsheet lệnh chạy](#11-cheatsheet-lệnh-chạy)
12. [Câu hỏi vấn đáp + trả lời ngắn](#12-câu-hỏi-vấn-đáp--trả-lời-ngắn)
13. [Giới hạn hiện tại và hướng bài sau](#13-giới-hạn-hiện-tại-và-hướng-bài-sau)

---

## 1. Nắm bài trong 5 phút

**Bài toán:** Bài 1 đã biến packet thành event JSON. Nhưng dữ liệu đó *chưa dùng được ngay*:
URI còn mã hoá (`%27%20OR%201%3D1`), body SMTP còn Base64, header viết hoa viết thường lộn xộn,
và mỗi packet đứng riêng lẻ — không biết packet nào thuộc phiên giao tiếp nào.

Bài 2 thêm **3 module trung gian** để sửa đúng 3 vấn đề đó:

```text
Bài 1 (Packet Capture & Parser) → Decoder → Preprocessor → Flow/Connection Tracker
```

| Module | Sửa vấn đề gì | File |
|---|---|---|
| Decoder | Dữ liệu bị **mã hoá/biểu diễn** → dạng đọc được | `decoder.py` |
| Preprocessor | Dữ liệu **không nhất quán / thiếu field** → một biểu diễn chuẩn | `preprocessor.py` |
| Flow tracker | Packet **đứng riêng lẻ** → gắn vào flow hai chiều + thống kê | `flow_tracker.py` |

**Sản phẩm cuối:** chạy 1 lệnh, sinh **2 file JSON Lines**:

```bash
python main.py --pcap test.pcap --output events.jsonl --flows-output flows.jsonl
```

**5 ý cốt lõi cần nhớ:**

| # | Ý | Vì sao |
|---|---|---|
| 1 | **Không sửa Bài 1**, chỉ import `parse_packet()` | Đề nói "mở rộng kết quả bài 1"; sửa lại là làm hỏng bài đã nộp |
| 2 | **Không ghi đè dữ liệu gốc**, chỉ thêm field `decoded_*` | Cần giữ raw để đối chiếu/điều tra (đề: "raw URI còn nguyên") |
| 3 | **Port/payload mã hoá không được đoán bừa** | Base64 chỉ giải khi header nói rõ; `+` chỉ là dấu cách trong form |
| 4 | **Một packet lỗi không được làm dừng chương trình** | IDS chạy 24/7; đề yêu cầu rõ ở mục 2 |
| 5 | **Flow là 2 chiều**, không phải 1 chiều | A→B và B→A phải **cùng** `flow_id`, chỉ khác `direction` |

**Bản đồ yêu cầu đề bài → code:**

| Mục đề | Nội dung | Nằm ở đâu |
|---|---|---|
| §2 | Lỗi decode/normalize/track xử lý an toàn; timeout/size/policy cấu hình được | `main.py::process_event` + 4 tham số CLI |
| §3 | HTTP URL/percent + form decoding | `decoder.py::_percent`, `_http` |
| §3 | HTML entity decoding | `decoder.py::_http` (`html.unescape`) |
| §3 | SMTP/MIME Base64 + Quoted-Printable theo header | `decoder.py::_mime`, `_transfer` |
| §3 | Character decoding ASCII/UTF-8, không crash khi byte lỗi | `decoder.py::_text`, `decode_status=PARTIAL` |
| §4 | Validation (field, port, timestamp, protocol) | `preprocessor.py::preprocess_event` |
| §4 | Normalization (protocol, IP/domain, header name, URI/path, timestamp) | cùng hàm trên |
| §4 | Missing/unsupported data → `null`/`[]`, mark hoặc skip | `SCALAR_FIELDS`, `--invalid-policy` |
| §4 | Metadata `preprocess_status`, `processing_action`, `reason` | cuối `preprocess_event` |
| §5.1 | Nhận diện flow + direction | `flow_tracker.py::track_event` |
| §5.2 | TCP state: NEW/HANDSHAKE, ESTABLISHED, CLOSING, CLOSED/RESET | `_tcp_handshake`, `_tcp_close` |
| §5.3 | UDP flow + idle timeout cho cả TCP/UDP | `_new_flow`, `expire_flows` |
| §5.4 | Thống kê tối thiểu trên mỗi flow | `_new_flow` + `track_event` |
| §6 | 14 test case bắt buộc T01–T14 | `TEST/` + `TEST/TESTCASES.md` |
| §10 | Commit theo task/test, thư mục TEST, khai báo AI | README + lịch sử commit |

---

## 2. Module này nằm ở đâu trong một IDS

```text
 (1) Capture      (2) Parse         (3) Decode +        (4) Feature      (5) Detection      (6) Alert
                  & Normalize          Preprocess +        Extractor        Engine
                                       Flow tracker
 ┌───────────┐   ┌──────────────┐   ┌────────────────┐  ┌────────────┐   ┌───────────────┐  ┌──────────┐
 │ bài 1     │ → │ bài 1        │ → │ BÀI 2 (đây)    │ →│ bài sau    │ → │ bài sau       │ →│ bài sau  │
 │ sniff/pcap│   │ packet→event │   │ event→event +  │  │ đếm, tính  │   │ signature /   │  │ log, chặn│
 │           │   │ JSON         │   │ flow           │  │ tỉ lệ      │   │ anomaly       │  │ (IPS)    │
 └───────────┘   └──────────────┘   └────────────────┘  └────────────┘   └───────────────┘  └──────────┘
```

**Vì sao phải có tầng Decode?** Kẻ tấn công *cố tình* mã hoá payload để né IDS:
`%27%20OR%201%3D1`, `&lt;script&gt;`, body Base64. Nếu detection engine so khớp chữ ký trên
chuỗi còn mã hoá thì **trượt hết**. Decoder đưa về dạng "người đọc được" trước khi so khớp.

**Vì sao phải có Flow tracker?** Một mình packet `SYN` không nói lên điều gì; nhưng
"500 SYN tới 500 port khác nhau trong 2 giây từ cùng 1 IP" là **port scan**. Muốn đếm như vậy
thì phải gom packet thành flow và giữ thống kê — đó chính là việc của tầng này.

> Câu chốt khi vấn đáp: *"Bài 2 làm sạch dữ liệu và gắn ngữ cảnh cho nó — biến event rời rạc
> thành flow có trạng thái, để tầng detection chỉ cần đếm và so chữ ký."*

---

## 3. Luồng dữ liệu chạy qua code

```text
  python main.py --pcap test.pcap --output events.jsonl --flows-output flows.jsonl
      │
      ▼
  main.main()                                  ← argparse, kiểm tra tham số
      │  new_tracker(tcp_timeout, udp_timeout) ← "active-flow table" rỗng
      ▼
  PcapReader(...) → next() cho từng packet
      │
      ▼
  packet_to_event(packet, packet_id)           ← gọi Bài 1 + lấy raw payload
      │    parse_packet()        → event 15 field của Bài 1
      │    event["packet_length"] = len(bytes(packet))
      │    payload = bytes(transport.payload)  ← BYTE GỐC, quan trọng (xem mục 10.1)
      ▼
  process_event(event, tracker, payload, max_decode_size, invalid_policy)
      │
      ├─ ① decode_event()      → thêm decoded_http_target / decoded_body / decoded_form
      │                           + decode_status + decode_reason
      ├─ ② preprocess_event()  → validate + normalize + preprocess_status/action/reason
      └─ ③ track_event()       → flow_id + direction + flow_state + thống kê
      │
      ▼
  write_jsonl(events, event)                   ← 1 dòng JSON / packet
  write_jsonl(flows, flow)                     ← flow vừa đóng (FIN/RST/timeout)
      │
      ▼
  finish_flows(tracker, reason)                ← kết thúc file: đẩy nốt flow còn lại
```

**Ví dụ trace thật** (lấy từ `TEST/output/http_request_events.jsonl`, packet 4):

```text
Packet: Ether / IP(10.0.0.1→10.0.0.2) / TCP(40000→80, PSH+ACK) / "POST /Search?q=%27%20OR%201%3D1 …"

① decode_event
   raw http_target = "/Search?q=%27%20OR%201%3D1"
   decoded_http_target = "/Search?q=' OR 1=1"
   decoded_body = "name=Alice Smith&literal=+", decoded_form = [{name:…}, {literal: +}]
   decode_status = "OK"

② preprocess_event
   headers {" HOST ":" EXAMPLE.TEST "} → {"host": "example.test"}
   preprocess_status = "valid", processing_action = "keep", normalized_http_target = "/Search?q=%27%20OR%201%3D1"

③ track_event
   flow_id = "flow_1", direction = "forward", flow_state = "ESTABLISHED", track_status = "OK"

→ cả phiên (9 packet) kết thúc bằng flow: CLOSED / tcp_fin,
  packet_count 9, byte_count 756, forward 5 packet/431 byte, backward 4 packet/325 byte, duration 8.0
```

---

## 4. Bản đồ file trong repo

```text
main.py               Đọc PCAP → decode → preprocess → track → ghi 2 file JSONL + CLI
decoder.py            Giải mã HTTP (percent, form, HTML) và MIME (base64, QP)
preprocessor.py       Validate + normalize + sinh metadata
flow_tracker.py       Dictionary flow 2 chiều + state TCP + thống kê + timeout
plan.md               Kế hoạch đơn giản của bài này
README.md             Tài liệu nộp bài (cách chạy, lựa chọn thiết kế, AI disclosure)
knowledge.md          File bạn đang đọc
TEST/
  common.py           sample_event(): 1 event mẫu dùng chung cho các test
  test_decoder.py     T01–T04 (decode)
  test_preprocessor.py T05, T06, T14 (normalize, missing field, event hỏng)
  test_flow_tracker.py T07–T13 (flow, state, UDP, timeout, thống kê)
  test_main.py        Test end-to-end qua CLI thật (chạy subprocess)
  make_evidence.py    Sinh lại pcap/ + output/ (bằng chứng)
  TESTCASES.md        Bảng map T01–T14 ↔ test ↔ kết quả thật
  results/            Kết quả chạy từng test (T01.txt … T14.txt, all_cases.txt, …)
  pcap/, output/      Bằng chứng đã sinh: capture + event log + flow log + summary.txt
docs/                 Đề bài PDF
```

**Thứ tự đọc code đề xuất:** `main.py::main` và `packet_to_event` (dữ liệu vào/ra) →
`decoder.py::decode_event` → `preprocessor.py::preprocess_event` → `flow_tracker.py::track_event`
→ `TEST/test_flow_tracker.py` (xem kết quả mong đợi).

---

## 5. Kiến thức nền tảng

### 5.1 Percent-encoding (URL encoding)

Byte không an toàn được viết `%XX` (hex). Bảng nhanh:

| Chuỗi | Nghĩa | Ví dụ đề bài |
|---|---|---|
| `%27` | `'` | `%27%20OR%201%3D1` → `' OR 1=1` |
| `%20` | dấu cách | |
| `%3D` | `=` | |
| `%2F` | `/` | |
| `%2527` | `%27` (mã hoá **2 lần**) | giải **1 lần** thôi, không giải tới khi hết |

Code: `decoder._percent()` dùng `urllib.parse.unquote`. **Chỉ giải 1 lần** — nếu giải lặp
("cho tới khi ổn định") thì dữ liệu `%2527` sẽ thành `'` và mất thông tin kẻ tấn công đã encode 2 lớp.

### 5.2 `application/x-www-form-urlencoded` — khác URL ở chỗ nào

Trong form data, `+` nghĩa là **dấu cách**, còn `%2B` mới là dấu `+` thật. Trong **URI path**
thì `+` vẫn là dấu `+` bình thường.

| Input | Trong URI path | Trong form body |
|---|---|---|
| `a+b` | `a+b` | `a b` |
| `a%2Bb` | `a+b` | `a+b` |

Code: `_percent(text, problems, form=False)` chọn `unquote` (path) hay `unquote_plus` (form).
Ngoài ra form còn được tách thành cặp name/value bằng `parse_qsl(..., keep_blank_values=True)`
→ field `decoded_form`.

### 5.3 HTML entity

Trong HTML, ký tự được viết bằng entity: `&lt;` = `<`, `&gt;` = `>`, `&amp;` = `&`,
`&quot;` = `"`, `&#39;` = `'`, `&#x27;` = `'`.
Đây là kỹ thuật rất hay dùng để né IDS: payload tấn công nằm trong DB, nhưng response trả về
dạng `&lt;script&gt;` nên nếu không decode thì không thấy được `<script>`.

Code: `html.unescape(body)` — chỉ áp dụng cho `text/*` và `application/xhtml+xml`
(tức "dữ liệu text phù hợp" theo đề). Chỉ giải 1 lần, nên `&amp;lt;` → `&lt;`.

### 5.4 MIME: Base64 và Quoted-Printable

SMTP vốn chỉ chở được ký tự ASCII 7-bit, nên thư điện tử mã hoá body:

```text
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64              ← header NÓI RÕ cách mã hoá

SGVsbG8=                                       ← base64 của "Hello"
```

| Encoding | Cách nhận biết | Ví dụ |
|---|---|---|
| `base64` | header `Content-Transfer-Encoding: base64` | `SGVsbG8=` → `Hello` |
| `quoted-printable` | header `...: quoted-printable` | `Xin ch=C3=A0o` → `Xin chào` |
| `7bit`/`8bit`/`binary` | header tương ứng | giữ nguyên byte |

**Nguyên tắc vàng:** *chỉ giải khi header nói rõ*. Nếu không có header mà vẫn thử base64 thì
chuỗi bình thường như `"From: alice"` sẽ bị biến thành rác — đó là lý do
`decode_event({"body": "SGVsbG8="})` trả `decode_status="SKIPPED"`.
QP cũng có kiểm tra lỗi: `=ZZ` (không phải hex) bị đánh dấu `PARTIAL`.

Trong MIME còn có `multipart/*`: một message chứa nhiều part, mỗi part có
`Content-Type` + `Content-Transfer-Encoding` riêng → code duyệt `message.walk()` và trả về
`mime_parts` (một phần tử cho mỗi part text).

### 5.5 Charset: ASCII và UTF-8

- **ASCII**: 7 bit, chỉ 128 ký tự đầu; byte `> 0x7F` là **sai**.
- **UTF-8**: mỗi ký tự 1–4 byte; dãy byte không hợp lệ (ví dụ `\xff\xfe`) là lỗi.

Đề yêu cầu tối thiểu ASCII + UTF-8 và **không crash khi gặp byte không hợp lệ**.
Code: `_text()` giải `strict`; nếu `UnicodeError` thì giải lại bằng `errors="replace"`
(ký tự `�`) **và** ghi lý do → `decode_status="PARTIAL"`. Charset lạ (`LookupError`) thì
quay về UTF-8 với `replace`.

### 5.6 Máy trạng thái TCP

```text
            SYN            SYN+ACK           ACK
   NEW ──────────► HANDSHAKE ────────► HANDSHAKE ────────► ESTABLISHED
     │                  │                                     │
     │                  │ ai đó gửi RST                        │ FIN
     │                  ▼                                     ▼
     └──────────────► RESET                              CLOSING
                                                            │ FIN chiều còn lại + 2 ACK
                                                            ▼
                                                          CLOSED
```

| Cờ | Ý nghĩa | Code dùng để |
|---|---|---|
| `SYN` | mở kết nối | đếm `SYN_count`, chuyển sang `HANDSHAKE` |
| `SYN+ACK` | server đồng ý | chỉ tính khi **đến từ chiều ngược lại** với SYN đầu |
| `ACK` | xác nhận | chỉ chuyển `ESTABLISHED` khi đã thấy SYN/ACK đúng chiều (xem bẫy 10.4) |
| `FIN` | kết thúc 1 chiều (half-close) | `CLOSING`; đủ **2 chiều + ACK** mới `CLOSED` |
| `RST` | huỷ kết nối ngay | `RESET`, đóng flow luôn |

### 5.7 UDP không có kết nối

UDP không có SYN/FIN/ACK. Vậy "flow UDP" = **các packet cùng bidirectional 5-tuple trong
khoảng thời gian hợp lệ**. DNS query (client→server) và response (server→client) là **1 flow**,
trạng thái của code là `ACTIVE`.

### 5.8 5-tuple và hai chiều

```text
key      = (src_ip, dst_ip, src_port, dst_port, protocol)    ← packet đầu tiên (A→B)
reverse  = (dst_ip, src_ip, dst_port, src_port, protocol)    ← packet B→A
```

Hai key trỏ về **cùng một dict flow**. Chiều nào bằng đúng `key` gốc → `forward`;
chiều ngược lại → `backward`. Endpoint A = bên gửi packet đầu tiên.

### 5.9 Byte count — quy ước của bài này

`byte_count` = tổng `len(bytes(packet))` = **cả header** Ethernet/IP/TCP (packet thật trên dây),
**không phải** độ dài text đã decode. Muốn chính xác thì phải định nghĩa rõ, vì nếu lấy
`payload_length` thì SYN/FIN (0 byte payload) sẽ đếm là 0 — sai ý nghĩa thống kê.

---

## 6. Giải thích từng file / từng hàm

### 6.1 `main.py` — tầng chạy + CLI + ghi log

#### `packet_to_event(packet, packet_id)` — cầu nối với Bài 1

```python
event = parse_packet(packet, packet_id)          # nguyên Bài 1, không sửa
event["packet_length"] = len(bytes(packet))      # thêm field phục vụ thống kê
transport = packet.getlayer(TCP) or packet.getlayer(UDP)
payload = bytes(transport.payload)[:event["payload_length"]]
return event, payload
```

Trả về **2 thứ**: event của Bài 1 **và** byte gốc của payload. Byte gốc là bắt buộc, vì
Bài 1 đã decode UTF-8 kiểu `errors="replace"` nên byte `\xff` đã thành `�` — không thể lấy lại.
Ngoài ra cắt payload theo `event["payload_length"]` để bỏ byte đệm (padding) mà Scapy có thể trả về.

#### `process_event(event, tracker, raw_payload, max_decode_size, invalid_policy)`

```python
try:    decoded = decode_event(event, raw_payload, max_decode_size)
except: decoded = {... decode_status: "ERROR", decode_reason: ...}
try:    processed = preprocess_event(decoded, invalid_policy)
except: return {... preprocess_status: "invalid", trackable: False ...}, []
try:    return track_event(tracker, processed)
except: ... tracker failed ...
```

Đây là **lưới an toàn của cả tầng**: 3 module được bọc riêng, module nào nổ thì packet đó bị
đánh dấu lỗi và **packet tiếp theo vẫn chạy bình thường**. Đúng yêu cầu §2 của đề.

#### `main(argv)` — CLI

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--pcap` | (bắt buộc) | file PCAP đầu vào |
| `--output` | `events.jsonl` | event đã xử lý (1 dòng/packet) |
| `--flows-output` | `flows.jsonl` | flow hoàn tất (1 dòng/flow) |
| `--tcp-timeout` | `120` | giây — TCP không có packet mới thì hết hạn |
| `--udp-timeout` | `30` | giây — UDP không có packet mới thì hết hạn |
| `--max-decode-size` | `65536` | kích thước tối đa khi decode (vượt → `PARTIAL`) |
| `--invalid-policy` | `mark` | `mark` = ghi event lỗi, `skip` = bỏ event lỗi |

Kiểm tra: timeout phải **hữu hạn và > 0** (`math.isfinite`, nên `nan`/`inf` bị chặn),
`--pcap`, `--output`, `--flows-output` phải là **3 file khác nhau**; sai → `parser.error` → exit code `2`.

Vòng lặp đọc: dùng `next(packets)` trong `while True` để phân biệt 3 tình huống:

| Tình huống | Xử lý | Ghi gì |
|---|---|---|
| `StopIteration` | hết file bình thường | `finish_flows(tracker, "eof")` |
| `KeyboardInterrupt` | người dùng Ctrl-C | kết thúc với `end_reason="interrupted"`, exit `130` |
| exception khác | record PCAP hỏng | 1 event `INCOMPLETE` "unreadable PCAP record …" rồi dừng êm (`read_error`) |

#### `write_jsonl(output, record)` và `finish_flows()`

`write_jsonl` ghi 1 dòng JSON rồi `flush()` ngay (log đọc được ngay cả khi đang chạy).
`finish_flows(tracker, reason)` đẩy **những flow còn lại trong bảng** ra file với
`close_reason = eof / interrupted / read_error` — nếu không làm bước này thì các flow chưa
kịp FIN/timeout sẽ **mất sạch**.

### 6.2 `decoder.py` — giải mã, không phá dữ liệu gốc

#### `decode_event(event, raw_payload=None, max_size=65536)`

```python
result.update(decoded_http_target=None, decoded_body=None, decoded_form=[])   # luôn có 3 field này
if protocol == "HTTP":                    _http(...)
elif protocol in ("SMTP", "UNKNOWN"):     _mime(...)     # UNKNOWN vì MIME có thể chưa được Bài 1 nhận ra
result["decode_status"] = "PARTIAL" if problems else ("OK" if handled else "SKIPPED")
result["decode_reason"]  = "; ".join(problems) or None
```

**Không bao giờ sửa `event` gốc**: hàm tạo `result = dict(event)` rồi mới thêm field.
Vì vậy `http_target`, `body`, `headers` giữ nguyên bản — đúng ví dụ T01 của đề.

#### `_http(result, raw_payload, max_size, problems)`

1. Chuẩn hoá `headers` (tên header viết thường, bỏ khoảng trắng thừa).
2. Dùng `email.message.Message` để đọc `Content-Type` + `charset` **đúng chuẩn**
   (thay vì tự cắt chuỗi `; charset=` bằng tay).
3. `http_target` → `decoded_http_target` bằng `_percent` (giải 1 lần).
4. **Lấy lại body từ byte gốc**: cắt tại `\r\n\r\n` (hoặc `\n\n`) trong `raw_payload`,
   nếu không tìm thấy dấu phân cách → `PARTIAL("incomplete HTTP headers")`.
5. Tuỳ `Content-Type`:
   - `application/x-www-form-urlencoded` → `decoded_body` (có `+` → space) + `decoded_form`.
   - `text/*` hoặc `application/xhtml+xml` → `html.unescape(body)`.
   - loại khác (json, ảnh…) → giữ nguyên, không unescape.

#### `_text()`, `_percent()`, `_bounded()`, `_headers()`, `_transfer()`

| Hàm | Việc làm | Ghi chú |
|---|---|---|
| `_text` | giải byte theo charset | lỗi → `errors="replace"` + ghi lý do (không ném exception) |
| `_percent` | percent decode | regex `%(?![0-9a-fA-F]{2})` phát hiện `%GG`; `form=True` → `unquote_plus` |
| `_bounded` | cắt theo `max_size` | vượt → thêm lý do "decode size limit exceeded" → `PARTIAL` |
| `_headers` | tên header `lower().strip()` | giá trị không phải chuỗi → ghi lý do, bỏ qua |
| `_transfer` | base64 / quoted-printable | base64 `validate=True`; QP kiểm tra `=ZZ` là sai |

#### `_mime(result, raw_payload, max_size, problems)`

- Chỉ chạy khi **có bằng chứng MIME**: payload gốc (hoặc headers của event) chứa
  `Content-Type` / `Content-Transfer-Encoding` / `MIME-Version`. Không có → trả `False`
  → `decode_status="SKIPPED"`.
- Xử lý cả SMTP `DATA`: bỏ tiền tố `DATA\r\n` và kết thúc `\r\n.\r\n`, đồng thời bỏ dot-stuffing
  (`..` ở đầu dòng → `.`).
- Dùng `BytesParser(policy=policy.default)` để tách part; chỉ lấy part `text/*`
  (attachment nhị phân không decode ký tự).
- Mỗi part → 1 phần tử `mime_parts`: `{content_type, charset, transfer_encoding, decoded_body}`.
- `decoded_body` = các part nối bằng `\n`. Part hỏng (`part.defects`) → `PARTIAL`.
- Nếu event đang là `UNKNOWN` mà tìm được MIME → nâng `application_protocol` thành `SMTP`.

### 6.3 `preprocessor.py` — validate + normalize

#### `preprocess_event(event, invalid_policy="mark")`

Thứ tự xử lý:

| # | Việc | Kết quả |
|---|---|---|
| 1 | Kiểm tra JSON-compatible từng value | value lạ (`object()`) → `null` + ghi vào `invalid` |
| 2 | `setdefault` cho `SCALAR_FIELDS` | field thiếu → `null` (nhất quán, không `KeyError`) |
| 3 | `src_ip`/`dst_ip` qua `ip_address()` | `2001:0DB8::1` → `2001:db8::1`; sai → `null` + invalid |
| 4 | `src_port`/`dst_port`: chuỗi số → int; phải `0..65535` | `True` (bool) và `65536` đều invalid |
| 5 | `timestamp` qua `parse_timestamp()` | nhận ISO-8601 **và** epoch; naive → coi là UTC |
| 6 | `transport_protocol` viết hoa | phải là `TCP`/`UDP`, còn lại → invalid (`ICMP`, `UNKNOWN`) |
| 7 | `application_protocol` viết hoa | lạ → `UNKNOWN` + **partial** (không invalid: vẫn track được) |
| 8 | `packet_length`, `payload_length` ≥ 0 | `packet_length` thiếu/sai → invalid; `payload_length` thiếu → partial |
| 9 | `tcp_flags` | viết hoa, bỏ cờ lạ, sắp theo thứ tự chuẩn `FIN, SYN, RST, PSH, ACK, URG, ECE, CWR` |
| 10 | `tcp_sequence/tcp_acknowledgment` ≤ 2³²−1; `tcp_window` ≤ 65535 | sai → `null` + partial |
| 11 | `headers` | tên header viết thường; riêng `host` hạ chữ thường cả giá trị (domain không phân biệt hoa/thường) |
| 12 | `dns_questions`/`dns_answers` | tên miền hạ chữ thường + bỏ dấu `.` cuối; `CNAME/NS/PTR` hạ chữ thường cả `data` |
| 13 | `http_target` → `normalized_http_target` | chỉ **viết hoa `%xx` → `%XX`**, chặn CRLF/NUL; **không đổi hoa/thường của path** |
| 14 | `parse_status` ≠ OK, hoặc `decode_status` ∈ {PARTIAL, ERROR} | chuyển thành `partial` |

Kết quả cuối:

```python
result["preprocess_status"] = "invalid" if invalid else ("partial" if partial else "valid")
result["trackable"]        = not invalid                     # chỉ event invalid mới bị cấm track
result["processing_action"]= "skip"  nếu invalid & policy=skip
                             "mark"  nếu invalid hoặc partial
                             "keep"  nếu sạch
result["reason"]           = "; ".join(invalid + partial) or None
```

**Vì sao `reason` quan trọng?** Đề yêu cầu "reason khi cần" — khi IDS báo động sai, người điều tra
cần biết *vì sao* bản ghi đó bị đánh dấu, thay vì chỉ thấy một cờ đỏ vô nghĩa.

#### `parse_timestamp(value)`

```python
1700000000                    → 2023-11-14T22:13:20+00:00 (UTC)
"2024-01-01T07:00:00+07:00"   → 2024-01-01T00:00:00+00:00
"2024-01-01T00:00:00Z"        → 2024-01-01T00:00:00+00:00
"2024-01-01T00:00:00"         → gán tzinfo=UTC (không đoán theo giờ máy)
nan / inf / "bad time" / None → ValueError → invalid
```

### 6.4 `flow_tracker.py` — trái tim của bài

#### `new_tracker(tcp_timeout=120, udp_timeout=30)`

```python
{"active_flows": {}, "next_id": 1, "tcp_timeout": ..., "udp_timeout": ..., "_clock": None}
```

Chỉ là **một dictionary** — không cần class, dễ in ra để debug. `active_flows` chính là
"active-flow table" mà đề nhắc tới.

#### `track_event(tracker, event)` → `(event đã gắn flow, danh sách flow vừa đóng)`

```python
result = preprocess_event(event, policy)         # ① chuẩn hoá lại (idempotent)
completed = expire_flows(tracker, result["timestamp"])   # ② dọn flow hết hạn TRƯỚC
if not result["trackable"]: return result, completed     # ③ event hỏng → không tạo flow
key     = (src_ip, dst_ip, src_port, dst_port, protocol)
reverse = (key[1], key[0], key[3], key[2], key[4])
# ④ tìm flow: key có sẵn → forward | reverse có sẵn → backward | không có → tạo flow mới
# ⑤ cập nhật start_time / last_seen / duration / packet_count / byte_count / per-direction
# ⑥ đếm SYN/ACK/FIN/RST (chỉ TCP)
# ⑦ _tcp_handshake() và _tcp_close() cập nhật state; nếu flow đóng → trả về `completed`
result.update(flow_id=..., direction=..., flow_state=..., track_status="OK")
```

Thứ tự **② trước ④** là chủ ý: nếu không, packet mới của một kết nối *mới* (trùng 5-tuple với
flow cũ đã hết hạn) sẽ bị gắn nhầm vào flow cũ.

#### `_tcp_handshake(flow, event, direction)`

```python
SYN (không kèm ACK)        → ghi nhớ _syn_direction, state = HANDSHAKE
SYN+ACK từ CHIỀU NGƯỢC LẠI → _synack_seen = True, state = HANDSHAKE
ACK từ ĐÚNG chiều gửi SYN  → state = ESTABLISHED
```

Chỉ áp dụng khi flow còn ở `NEW`/`HANDSHAKE` → dữ liệu sau đó không làm state nhảy lùi.

#### `_tcp_close(flow, event, direction)`

```python
RST                                     → state = RESET, đóng flow (tcp_rst)
ACK khi chiều kia đã gửi FIN            → đánh dấu đã ACK cho FIN đó
FIN                                     → _fin_seen[direction] = True, state = CLOSING
đủ 2 FIN + đủ 2 ACK                     → state = CLOSED, đóng flow (tcp_fin)
```

Khi flow đóng: `flow["close_reason"]`, `flow_snapshot(flow)` được ghi ra file và
`del active[key]` — đúng yêu cầu "giải phóng khỏi active-flow table".

#### `expire_flows(tracker, now)` và `finish_flows(tracker, reason)`

```python
timeout = tcp_timeout nếu protocol == "TCP" ngược lại udp_timeout
if tracker["_clock"] - flow["_last_seconds"] >= timeout:
    state = "CLOSED"; close_reason = "idle_timeout"; đẩy ra + xoá khỏi bảng
```

`tracker["_clock"]` = **max của mọi timestamp đã thấy** → file PCAP có packet lệch thứ tự thời gian
vẫn không làm flow hết hạn sai. Thời gian dùng là **timestamp trong packet** (`packet.time`),
không phải đồng hồ máy — nên test T12 chạy trong 0.001 giây mà vẫn kiểm tra được timeout 10 giây.

`finish_flows` đóng mọi flow còn lại với `close_reason` là lý do kết thúc file
(`eof`, `interrupted`, `read_error`); **state giữ nguyên như packet cho thấy**
(ESTABLISHED/ACTIVE) — không tự bịa ra CLOSED khi capture chỉ đơn giản là hết file.

#### `flow_snapshot(flow)`

```python
{k: v for k, v in flow.items() if not k.startswith("_")}
```

Các key `_start_seconds`, `_last_seconds`, `_syn_direction`, `_synack_seen`, `_fin_seen`,
`_fin_acked` là **nội bộ**, không được lộ ra file output. `deepcopy` để bản snapshot không đổi
khi flow tiếp tục nhận packet (test T13 kiểm tra đúng điều này).

### 6.5 `TEST/` — bộ test và bằng chứng

| File | Kiểm tra gì | Cách làm |
|---|---|---|
| `test_decoder.py` | T01–T04 | gọi trực tiếp `decode_event`, có cả byte lỗi thật |
| `test_preprocessor.py` | T05, T06, T14 | gọi `preprocess_event` với event méo (None, `NaN`, `True`, IP sai…) |
| `test_flow_tracker.py` | T07–T13 | event mẫu từ `common.sample_event`, timestamp cố định |
| `test_main.py` | End-to-end | chạy `main.py` thật bằng `subprocess`, đọc 2 file JSONL |
| `make_evidence.py` | Sinh bằng chứng | tạo pcap thật → chạy CLI → lưu `output/*.jsonl` + `summary.txt` |
| `common.py` | Dữ liệu dùng chung | `sample_event(reverse=True, **changes)` |

**Kỹ thuật test đáng nhớ:**

- **Không dùng `time.sleep()`**: mọi test timeout dùng timestamp cố định
  (`1700000000`, `1700000010`…) → test chạy tức thì mà vẫn đúng logic.
- `subprocess.run([...])` để test **đúng lệnh thật** như giảng viên sẽ chạy (đọc file, kiểm tra
  exit code, kiểm tra nội dung file output).
- `tcp_packet(flags, timestamp, reverse=...)` tạo packet TCP đủ trường (có MAC để Scapy không
  phải tra ARP — tránh warning và tránh phụ thuộc mạng).
- `wrpcap()` tạo PCAP thật → đi đúng đường Scapy `PcapReader`.

---

## 7. Event và flow output gồm những gì

### 7.1 Event (`events.jsonl`)

Giữ **toàn bộ field của Bài 1** (15 field chung + `http_*`/`dns_*`/`smtp_*`), rồi thêm:

| Nhóm | Field thêm | Ý nghĩa |
|---|---|---|
| Kích thước | `packet_length` | số byte thật của packet (dùng cho `byte_count`) |
| Decoder | `decoded_http_target`, `decoded_body`, `decoded_form` | dữ liệu đã giải mã (gốc vẫn còn) |
| Decoder | `mime_parts` | chỉ có khi xử lý MIME: list part text |
| Decoder | `decode_status`, `decode_reason` | `OK`/`PARTIAL`/`SKIPPED`/`ERROR` + lý do |
| Preprocessor | `normalized_http_target` | URI đã chuẩn hoá (viết hoa `%xx`) |
| Preprocessor | `preprocess_status`, `processing_action`, `trackable`, `reason` | kết quả kiểm tra/normalize |
| Tracker | `flow_id`, `direction`, `flow_state`, `track_status` | gắn vào flow nào, chiều nào, trạng thái, có track được không |

### 7.2 Flow (`flows.jsonl`) — đúng danh sách tối thiểu §5.4

| Nhóm | Field |
|---|---|
| Định danh | `flow_id`, `protocol`, `application_protocol`, `endpoint_a`, `endpoint_b` |
| Thời gian | `start_time`, `last_seen`, `duration` |
| Tổng thể | `packet_count`, `byte_count` |
| Hai chiều | `forward_packet_count`, `backward_packet_count`, `forward_byte_count`, `backward_byte_count` |
| TCP | `SYN_count`, `ACK_count`, `FIN_count`, `RST_count`, `state` |
| Thêm | `close_reason` (`tcp_fin` / `tcp_rst` / `idle_timeout` / `eof` / `interrupted` / `read_error`) |

---

## 8. Các trạng thái

### 8.1 `decode_status`

| Giá trị | Nghĩa | Ví dụ |
|---|---|---|
| `OK` | giải mã xong, không có vấn đề | `%27%20OR%201%3D1` → `' OR 1=1` |
| `PARTIAL` | giải mã được nhưng có lỗi/cắt bớt | byte `\xff`, `%GG`, vượt `max-decode-size` |
| `SKIPPED` | không phải loại cần decode | packet DNS, HTTP không MIME header |
| `ERROR` | input không dùng được (không phải dict) | hiếm, chỉ ở lưới an toàn |

### 8.2 `preprocess_status`

| Giá trị | Nghĩa | Có track được? |
|---|---|---|
| `valid` | mọi thứ đúng, sạch | có |
| `partial` | thiếu field phụ / app protocol lạ / parser báo MALFORMED | **có** (dữ liệu vẫn hữu ích) |
| `invalid` | thiếu IP/port/timestamp/protocol, value không JSON | không |

### 8.3 `track_status` và `flow_state`

`track_status` = `OK` (đã gắn flow) hoặc `SKIPPED` (event invalid, không tạo flow).
`flow_state` = `NEW` → `HANDSHAKE` → `ESTABLISHED` → `CLOSING` → `CLOSED`, hoặc `RESET`;
UDP thì `ACTIVE`.

---

## 9. Bảng quyết định thiết kế

| Vấn đề | Chọn | Vì sao | Thay thế đã cân nhắc |
|---|---|---|---|
| Có sửa Bài 1 không? | **Không**, import `parse_packet()` | Giữ nguyên bài đã nộp, đúng tinh thần "mở rộng" | copy code sang (trùng lặp, lệch hành vi) |
| Lấy byte gốc cho decoder | **truyền `raw_payload` riêng** | Bài 1 đã thay byte lỗi bằng `�`, không lấy lại được | decode từ `event["body"]` (mất byte gốc) |
| Field đã giải mã | **thêm `decoded_*`, không ghi đè** | Đề yêu cầu "raw URI còn nguyên"; cần đối chiếu khi điều tra | ghi đè `http_target` (mất bằng chứng) |
| Form vs URI | **`unquote_plus` chỉ cho form** | `+` chỉ là space trong form data | dùng `unquote_plus` cho tất cả (sai với path) |
| Giải mã nhiều lần? | **1 lần duy nhất** | `%2527` là dấu hiệu encode 2 lớp, không phải lỗi | lặp tới khi ổn định (mất thông tin) |
| MIME | **chỉ theo header** | `"From: alice"` mà base64-decode sẽ thành rác | luôn thử base64 (sai rất nhiều) |
| Thư viện MIME | **`email.parser.BytesParser`** | Chuẩn, xử lý multipart + charset + boundary | tự tách chuỗi (dễ sai) |
| Lưu flow | **dict + `flow_N`** | Dễ in/debug, không cần class; ID ổn định trong 1 lần chạy | class Flow (nhiều code hơn) |
| Khoá flow | **5-tuple + tra ngược** | Đúng đề: 2 chiều phải cùng `flow_id` | 4-tuple riêng mỗi chiều (tách sai thành 2 flow) |
| Điều kiện ESTABLISHED | **SYN → SYN/ACK (chiều ngược) → ACK** | Một ACK đơn lẻ không chứng minh được gì (bẫy 10.4) | cứ thấy ACK là ESTABLISHED (sai) |
| Đóng flow | **RST ngay; FIN cần cả 2 chiều + ACK** | TCP cho phép half-close, 1 FIN chưa phải kết thúc | 1 FIN là CLOSED (sai khi mới half-close) |
| Timeout | **theo timestamp trong packet** | PCAP phát lại nhanh hơn thời gian thật rất nhiều | `time.time()` (mọi flow hết hạn sai) / `sleep` (chậm test) |
| Flow còn lại khi hết file | **đẩy ra với `close_reason="eof"`** | Không đẩy thì mất dữ liệu; không bịa thành `CLOSED` | bỏ qua (mất flow mới nhất) |
| `byte_count` | **`len(bytes(packet))`** | Đúng nghĩa "byte trên dây"; SYN/FIN vẫn được tính | `payload_length` (SYN/FIN = 0 byte) |
| Event lỗi | **`mark` mặc định, `skip` tuỳ chọn** | Đề cho phép cấu hình; mặc định giữ để điều tra | luôn skip (mất bằng chứng) |
| An toàn | **3 lớp bọc riêng trong `process_event`** | 1 packet lỗi không được giết tiến trình (§2) | 1 lớp `try` duy nhất |

---

## 10. Cái bẫy thực tế đã gặp

1. **`event["body"]` của Bài 1 không còn byte gốc.** Bài 1 giải UTF-8 với `errors="replace"`,
   nên `\xff` đã thành `�`; muốn biết byte gốc thì **buộc phải** truyền `raw_payload` xuống decoder.
   Đây là lý do `packet_to_event()` trả về 2 giá trị.
2. **Không được dùng `--unknown-policy skip` của Bài 1.** Packet SYN/ACK/FIN **không có payload**
   → Bài 1 xếp application là `UNKNOWN`; nếu skip thì mất sạch handshake, flow tracker không còn
   gì để theo dõi. Bài 2 tự quản policy riêng (`--invalid-policy`, chỉ áp cho event **invalid**).
3. **Record PCAP bị cắt có thể không ném exception.** Scapy vẫn trả về 1 packet với
   `parse_status="INCOMPLETE"` ("truncated IPv4 payload"), nên code phải kiểm tra *cả hai* đường:
   `except` khi đọc **và** trạng thái `INCOMPLETE` của event.
4. **Một ACK đơn lẻ không phải là handshake.** Nếu chỉ nhìn "có ACK" là chuyển
   `ESTABLISHED` thì flow scan (SYN rồi RST) cũng bị coi là kết nối thành công. Code yêu cầu
   SYN/ACK đến **từ chiều ngược lại** rồi mới chấp nhận ACK tiếp theo.
5. **Một FIN chưa đóng flow.** TCP half-close: A gửi FIN nhưng B vẫn gửi dữ liệu được. Nếu đóng ngay
   thì thống kê sai. Code cần **cả 2 FIN + cả 2 ACK** mới chuyển `CLOSED`.
6. **Timeout phải dùng timestamp trong packet, không phải `time.time()`.** File PCAP 1 giờ có thể
   đọc trong 1 giây; nếu dùng đồng hồ máy thì chẳng flow nào hết hạn (hoặc hết hạn sai hết).
   Test T12 cũng nhờ vậy mà kiểm tra timeout 10 giây trong 0.001 giây.
7. **Dọn flow hết hạn phải chạy TRƯỚC khi ghép packet mới.** Nếu không, packet của kết nối mới
   (trùng 5-tuple) sẽ bị ghép vào flow cũ → sai cả `flow_id` lẫn thống kê.
8. **`+` không phải dấu cách ở mọi nơi.** Chỉ trong form body. Trong URI path, `+` là `+`.
9. **`%2527` chỉ giải 1 lần.** Giải "tới khi hết `%`" là tự tạo lỗ hổng/đọc sai dữ liệu tấn công.
10. **Không được đoán encoding.** Chỉ base64/QP khi header nói rõ; nếu không, chuỗi bình thường sẽ
    thành rác. Test T03 có hẳn nhánh `SKIPPED` cho trường hợp này.
11. **Scapy `policy.default` trả payload dạng `str`** cho part base64/QP, nên phải encode lại
    (`ascii`, `surrogateescape`) trước khi `b64decode`/`quopri.decodestring`; nếu không sẽ lỗi kiểu.
12. **`packet.getlayer(TCP) or packet.getlayer(UDP)`** dùng chung cho cả TCP/UDP nhưng phải cắt
    payload theo `event["payload_length"]`, vì `bytes(transport.payload)` có thể chứa byte đệm.
13. **`nan`/`inf` là số hợp lệ với `float()`.** `--udp-timeout nan` không bị argparse chặn;
    phải kiểm tra `math.isfinite()` (test end-to-end kiểm tra exit code `2`).
14. **Hai file output không được trùng nhau (và không trùng file input)**, nếu không sẽ ghi đè
    dữ liệu đang đọc → code kiểm tra bằng `Path.resolve()`.
15. **`json.dumps` có thể nổ nếu event còn giá trị lạ.** Vì vậy `preprocess_event` kiểm tra
    JSON-compatible từng value trước, và `write_jsonl` dùng `allow_nan=False`.

---

## 11. Cheatsheet lệnh chạy

```bash
# ---------- chạy chương trình ----------
python main.py --pcap test.pcap
python main.py --pcap test.pcap --output events.jsonl --flows-output flows.jsonl
python main.py --pcap test.pcap --tcp-timeout 60 --udp-timeout 15
python main.py --pcap test.pcap --max-decode-size 4096        # giới hạn kích thước decode
python main.py --pcap test.pcap --invalid-policy skip         # bỏ event invalid

# ---------- kiểm thử ----------
python -m unittest discover -s TEST -v                       # toàn bộ (18 test)
python -m unittest TEST.test_flow_tracker.FlowTests.test_T07_tcp_handshake -v
python TEST/make_evidence.py                                 # sinh lại pcap/ + output/

# ---------- kiểm tra bài 1 vẫn ổn ----------
cd "../BaiTap1:Packet_CAPTURER_AND_PARSER" && python -m unittest discover -s TEST

# ---------- xem kết quả ----------
head -1 events.jsonl | python -m json.tool                   # 1 event cho dễ đọc
cat flows.jsonl | python -m json.tool --json-lines           # toàn bộ flow
cat TEST/output/summary.txt                                  # bản tóm tắt bằng chứng
```

---

## 12. Câu hỏi vấn đáp + trả lời ngắn

**A. Kiến trúc**

1. **Bài 2 làm gì?** — Nhận event của Bài 1, giải mã dữ liệu bị mã hoá, chuẩn hoá + kiểm tra,
   rồi gắn vào flow hai chiều kèm thống kê; xuất 2 file JSONL.
2. **Vì sao không sửa Bài 1?** — Đề nói "mở rộng kết quả Bài 1"; sửa lại vừa hỏng bài cũ vừa
   trùng lặp code. Bài 2 chỉ import `parsers.parse_packet`.
3. **Vì sao phải truyền `raw_payload` xuống decoder?** — Vì Bài 1 đã giải UTF-8 với
   `errors="replace"`, byte gốc đã mất; muốn giải mã đúng (base64/QP/charset) thì cần byte thật.
4. **Vì sao event lỗi vẫn được ghi?** — Để điều tra: packet `MALFORMED` chính là dấu hiệu tấn công
   (fuzzing, né IDS). Mặc định `mark`; ai muốn gọn thì `--invalid-policy skip`.
5. **Đầu ra gồm mấy file, vì sao tách?** — 2 file: event theo từng packet (chi tiết) và flow theo
   từng phiên (tổng hợp). Tách ra để tầng sau chọn đúng mức chi tiết cần dùng.

**B. Decoder (§3)**

6. **Percent decode khác form decode thế nào?** — Form đổi `+` thành dấu cách, URI path thì không;
   form còn tách thành cặp name/value.
7. **Vì sao chỉ giải 1 lần?** — `%2527` là dữ liệu được encode 2 lớp, giải tiếp là bóp méo dữ liệu
   gốc của kẻ tấn công.
8. **HTML entity để làm gì?** — Kẻ tấn công viết `&lt;script&gt;` để né so khớp chữ ký;
   `html.unescape` đưa về `<script>`.
9. **Khi nào giải base64/QP?** — Chỉ khi `Content-Transfer-Encoding` nói rõ; không có header thì
   `decode_status="SKIPPED"`.
10. **Gặp byte không phải UTF-8 thì sao?** — Giải lại bằng `errors="replace"`, thêm ký tự `�`,
    đánh dấu `PARTIAL` + lý do, **không crash**.
11. **`max-decode-size` để làm gì?** — Chặn payload khổng lồ (zip bomb, base64 100 MB) làm tốn CPU/RAM;
    vượt thì cắt và đánh dấu `PARTIAL`.
12. **Vì sao giữ lại cả field gốc?** — Đề yêu cầu "raw URI còn nguyên"; và khi phân tích cần biết
    dữ liệu gốc trước khi giải mã.

**C. Preprocessor (§4)**

13. **Validation kiểm những gì?** — IP, port 0–65535, timestamp, transport protocol (TCP/UDP),
    kích thước ≥ 0, value phải JSON-compatible.
14. **Normalization làm gì?** — Viết hoa tên protocol, chuẩn hoá IP (`2001:0DB8::1` → `2001:db8::1`),
    tên header viết thường, tên miền hạ chữ thường + bỏ dấu `.` cuối, timestamp về UTC.
15. **Vì sao KHÔNG hạ chữ thường URI/path?** — Path phân biệt hoa/thường (`/Login` ≠ `/login`);
    đổi là sai nghĩa. Chỉ viết hoa `%xx` → `%XX`.
16. **`valid` / `partial` / `invalid` khác nhau?** — `valid` sạch; `partial` thiếu field phụ hoặc app
    protocol lạ (vẫn track); `invalid` thiếu field bắt buộc (không track).
17. **Missing field xử lý ra sao?** — Scalar → `null`, list → `[]`, dict → `{}`; không bao giờ
    `KeyError`; và trong `reason` ghi rõ field nào thiếu.

**D. Flow tracker (§5)**

18. **Flow được nhận diện thế nào?** — 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`;
    tra cả key gốc và key đảo chiều để 2 chiều về cùng 1 flow.
19. **`forward` vs `backward`?** — Bên gửi packet đầu tiên là endpoint A; A→B là `forward`,
    B→A là `backward`.
20. **Vì sao packet không payload vẫn phải giữ?** — SYN/ACK/FIN không có payload nhưng chính chúng
    quyết định trạng thái kết nối.
21. **Khi nào ESTABLISHED?** — Sau SYN → SYN/ACK (đúng chiều ngược lại) → ACK.
    Một ACK đơn lẻ không đủ.
22. **Khi nào CLOSED?** — RST thì `RESET` ngay; FIN thì `CLOSING`, cần cả 2 chiều FIN + ACK mới `CLOSED`.
23. **UDP khác gì?** — Không có state/handshake; packet cùng tuple đảo chiều trong thời gian hợp lệ
    là 1 flow, state `ACTIVE`.
24. **Idle timeout hoạt động thế nào?** — Mỗi flow ghi `last_seen`; packet mới đến thì dọn những flow
    có `now − last_seen ≥ timeout` (TCP/UDP timeout khác nhau), đẩy ra file rồi xoá khỏi bảng.
25. **Vì sao dùng timestamp của packet?** — PCAP phát lại nhanh hơn thời gian thực; dùng đồng hồ máy
    là sai. Đây cũng là lý do test timeout chạy tức thì.
26. **Thống kê tối thiểu gồm gì?** — `flow_id`, `protocol`, `application_protocol`, 2 endpoint,
    `start_time`/`last_seen`/`duration`, `packet_count`/`byte_count`, 4 cặp đếm hai chiều,
    `SYN/ACK/FIN/RST_count` và `state`.
27. **`byte_count` tính thế nào?** — `len(bytes(packet))` (cả header) để SYN/FIN cũng được tính.
28. **Flow hết hạn có bị giữ lại không?** — Không: ghi ra `flows.jsonl` rồi `del` khỏi
    `active_flows` (đúng đề: "giải phóng khỏi active-flow table").
29. **Nếu kết nối mới trùng 5-tuple với flow vừa hết hạn?** — Vì đã bị xoá trước khi ghép packet,
    nó được cấp `flow_id` mới — không trộn 2 phiên vào nhau.
30. **Cut PCAP thì sao?** — Packet đọc được vẫn parse bình thường; record hỏng/cắt thành 1 event
    `INCOMPLETE` rồi dừng êm, exit code `0`; flow còn lại vẫn được đẩy ra với `close_reason` tương ứng.

**E. Kiểm thử**

31. **Test timeout mà không `sleep`?** — Dùng timestamp cố định trong packet (T12), nên kiểm tra
    được cả TCP 10 giây lẫn UDP 5 giây ngay lập tức.
32. **Test nào chạy qua CLI thật?** — `test_main.py` dùng `subprocess` chạy `main.py` như giảng viên
    sẽ chạy, rồi kiểm tra exit code và nội dung 2 file JSONL.
33. **Bằng chứng test ở đâu?** — `TEST/results/T01.txt … T14.txt` (từng case),
    `TEST/pcap/` + `TEST/output/` (dữ liệu chạy thật), `TEST/TESTCASES.md` (bảng map),
    và `summary.txt` (tóm tắt flow).

---

## 13. Giới hạn hiện tại và hướng bài sau

| Giới hạn | Ảnh hưởng | Bài sau cần gì |
|---|---|---|
| Không ghép TCP stream | HTTP/SMTP dài nhiều packet chỉ đọc được phần đầu; body lớn bị cắt | Bộ đệm theo flow + `seq`, ghép theo thứ tự |
| Không ghép IP fragment | Packet phân mảnh không có payload đầy đủ | Dùng `fragment offset`/`MF` |
| Không giải mã TLS/DoH/DoT | HTTPS không đọc được nội dung (đề ghi rõ **không bắt buộc**) | Chỉ dùng metadata (SNI, JA3, kích thước, thời gian) |
| Chỉ chạy từ PCAP | Không có `--interface` như Bài 1 (đề Bài 2 nhận packet/event từ Bài 1) | Ghép trực tiếp `sniff()` của Bài 1 vào `process_event` |
| Chưa phát hiện tấn công | Đây mới là tầng làm sạch + gắn ngữ cảnh | Feature extractor + detection engine |

**Field sẵn sàng cho bài sau (Feature Extractor / Detection):**

| Phát hiện | Dựa vào |
|---|---|
| Port scan | `src_ip` + nhiều `dst_port` khác nhau, `SYN_count` cao, `state` không bao giờ `ESTABLISHED` |
| SYN flood | `SYN_count` lớn, `packet_count`/`duration` bất thường |
| HTTP attack payload | `decoded_http_target`, `decoded_body`, `decoded_form`, `headers` (đã decode!) |
| DNS tunneling | `application_protocol=DNS`, `dns_questions`, độ dài tên miền, tần suất packet |
| SMTP/MIME abuse | `mime_parts`, `decoded_body`, `application_protocol=SMTP`, số flow |
| Né IDS bằng encoding | `decode_status=PARTIAL` / `decode_reason`, `parse_status=MALFORMED` |
| Quét kết nối thất bại | `RST_count` cao, `close_reason=tcp_rst` |

---

### Ghi chú cuối

* Tài liệu này giải thích **code thật trong repo** — hãy mở code đọc kèm để kiểm chứng, vì vấn đáp
  yêu cầu bạn *hiểu và giải thích được* mã nguồn mình nộp.
* Việc dùng AI đã được khai báo trong `README.md` (mục *AI assistance disclosure*) theo yêu cầu §10.
* Nếu bị hỏi "vì sao chỗ này làm thế?", ưu tiên trả lời bằng **lý do thiết kế** (mục 9) và
  **cái bẫy đã gặp** (mục 10) — đó là phần thể hiện bạn thực sự hiểu bài.
