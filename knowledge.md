# knowledge.md — Hiểu toàn bộ bài tập & code

> Tài liệu học tập cho **Bài tập 1: Packet Capture & Parser cho IDS** (NT204).
> Viết theo kiểu "dễ hiểu nhất có thể": giải thích khái niệm trước, rồi mới chỉ vào code.
> Mọi số liệu, tên hàm, tên field đều khớp với code thật trong repo này.
>
> **Cách học hiệu quả:** đọc mục 1–4 để nắm bức tranh, sau đó mở code và đọc kèm mục 6.
> Mục 10 (cái bẫy) và mục 12 (câu hỏi vấn đáp) là phần quan trọng nhất khi bị hỏi.

---

## Mục lục

1. [Nắm bài trong 5 phút](#1-nắm-bài-trong-5-phút)
2. [Module này nằm ở đâu trong một IDS](#2-module-này-nằm-ở-đâu-trong-một-ids)
3. [Luồng dữ liệu chạy qua code](#3-luồng-dữ-liệu-chạy-qua-code)
4. [Bản đồ file trong repo](#4-bản-đồ-file-trong-repo)
5. [Kiến thức mạng nền tảng](#5-kiến-thức-mạng-nền-tảng)
6. [Giải thích từng file / từng hàm](#6-giải-thích-từng-file--từng-hàm)
7. [Event chuẩn hoá gồm những gì](#7-event-chuẩn-hoá-gồm-những-gì)
8. [Phân loại lỗi: OK / UNSUPPORTED / INCOMPLETE / MALFORMED](#8-phân-loại-lỗi)
9. [Bảng quyết định thiết kế](#9-bảng-quyết-định-thiết-kế)
10. [Cái bẫy thực tế đã gặp khi làm bài](#10-cái-bẫy-thực-tế-đã-gặp)
11. [Cheatsheet lệnh chạy](#11-cheatsheet-lệnh-chạy)
12. [Câu hỏi vấn đáp + trả lời ngắn](#12-câu-hỏi-vấn-đáp--trả-lời-ngắn)
13. [Giới hạn hiện tại và hướng bài sau](#13-giới-hạn-hiện-tại-và-hướng-bài-sau)

---

## 1. Nắm bài trong 5 phút

**Bài toán:** một IDS (Intrusion Detection System) muốn phát hiện tấn công thì trước hết phải
*đọc được* lưu lượng mạng và *hiểu* nó. Bài tập 1 yêu cầu xây đúng phần đó: **bắt packet →
phân tích (parse) → chuyển thành event chuẩn hoá**.

**Sản phẩm cuối:** một chương trình Python, chạy được 2 chế độ:

```bash
python main.py --interface eth0     # bắt trực tiếp từ card mạng
python main.py --pcap test.pcap     # đọc từ file PCAP
```

Cả hai chạy **cùng một pipeline** và in ra **JSON Lines**, mỗi packet 1 dòng:

```json
{"packet_id": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000,
 "dst_port": 80, "transport_protocol": "TCP", "application_protocol": "HTTP",
 "http_method": "GET", "http_target": "/index.html", "parse_status": "OK", ...}
```

**4 ý cốt lõi cần nhớ:**

| # | Ý | Vì sao |
|---|---|---|
| 1 | **Không có 2 parser riêng** cho live và PCAP | Đề bắt buộc; tránh code trùng lặp, tránh 2 nơi xử lý lệch nhau |
| 2 | **Port chỉ là gợi ý**, phải nhìn payload | Service có thể chạy port khác (HTTP 18080, DNS 53000…) |
| 3 | **Không bao giờ crash** vì packet lạ/hỏng | IDS chạy 24/7, một packet lỗi không được làm chết chương trình |
| 4 | **Output phải sạch, không chứa raw packet** | Bài sau (detection engine) chỉ làm việc với event, không cần Scapy |

**Bản đồ yêu cầu đề bài → code:**

| Mục đề | Nội dung | Nằm ở đâu |
|---|---|---|
| §2.1.1 | Live capture | `main.py::Capture_through_interface` |
| §2.1.2 | PCAP import, cùng pipeline | `main.py::Capture_through_pcap` |
| §3 | Pipeline 5 tầng | `parsers/pipeline.py::parse_packet` |
| §4 | Nhận diện trên non-standard port | `detect_application_protocol` + các hàm `_looks_like_*` |
| §5 | App detection, UNKNOWN hoặc skip | `detect_application_protocol` + `--unknown-policy` |
| §6 | Output JSON-compatible chuẩn hoá | `parsers/schema.py` |
| §7 | Error handling | `parsers/errors.py` + `_parse_safely` + handler lỗi PCAP |
| §8 | Ghi kết quả ra file JSON Lines | `PacketEventWriter` + `--output` |
| §9 | 12 test case bắt buộc | `TEST/test_mandatory_cases.py` + `TEST/pcap/` |
| §10 | GitHub: commit theo task, thư mục TEST, ghi rõ dùng AI | `Readme.md`, lịch sử commit |

---

## 2. Module này nằm ở đâu trong một IDS

Một IDS thường chia thành các tầng. Bài 1 làm tầng 1–2, các bài sau làm tầng 3–5:

```text
        (1) Capture          (2) Parse & Normalize     (3) Detection       (4) Alert        (5) Response
  ┌──────────────────┐   ┌────────────────────────┐  ┌───────────────┐  ┌───────────┐   ┌────────────┐
  │ card mạng / PCAP │ → │ packet → IDS event chuẩn│ →│ signature /   │→ │ log, cảnh │→  │ chặn (IPS) │
  │  (bài 1)         │   │  (bài 1)                │  │ anomaly, scan │  │ báo        │   │            │
  └──────────────────┘   └────────────────────────┘  └───────────────┘  └───────────┘   └────────────┘
```

**Vì sao phải "chuẩn hoá" (normalize)?** Nếu tầng detection phải tự gọi Scapy để lấy `dst_port`,
thì mỗi khi đổi thư viện capture phải sửa toàn bộ detection. Chuẩn hoá nghĩa là: **mọi tầng sau
chỉ cần biết một cấu trúc duy nhất** — đó là `dict` event với các key cố định.

> Câu chốt khi vấn đáp: *"Bài 1 biến packet thô thành event, để các bài sau không cần chạm vào
> raw packet nữa."*

---

## 3. Luồng dữ liệu chạy qua code

```text
  Người dùng
      │  python main.py --pcap test.pcap
      ▼
  main.main()                         ← đọc tham số dòng lệnh (argparse)
      │
      ├─ chọn nguồn: Capture_through_interface()  hoặc  Capture_through_pcap()
      │        │
      │        ▼
      │   Scapy: sniff(iface=...)  hoặc  PcapReader(...).__next__()
      │        │   mỗi packet → gọi callback (packet_handler)
      │        ▼
      │   PacketEventWriter.__call__(packet)      ← tầng bao ngoài, có đếm packet_id
      │        │
      │        ▼
      │   _parse_safely() → parse_packet(packet, packet_id)   ← LÕI
      │        │
      │        ├─ Bước 1  _parse_ipv4()               → src_ip, dst_ip, payload
      │        ├─ Bước 2  _parse_transport()          → TCP/UDP + port + flags + payload
      │        ├─ Bước 3  detect_application_protocol()→ HTTP / DNS / SMTP / UNKNOWN
      │        ├─ Bước 4  parse_application_payload() → các field riêng của protocol
      │        └─ Bước 5  (đóng gói) → dict event + parse_status
      │        │
      │        ▼
      │   _write_event(): json.dumps(event) + "\n" + flush
      ▼
  stdout  hoặc  file --output events.jsonl   (JSON Lines, 1 event = 1 dòng)
```

**Ví dụ trace thật** (lấy từ `TEST/output/http_get.jsonl`):

```text
Packet: Ether / IP(10.0.0.1→10.0.0.2) / TCP(40000→80, PSH+ACK) / "GET /index.html HTTP/1.1…"
  _parse_ipv4      → src_ip=10.0.0.1 dst_ip=10.0.0.2 network_protocol=IPv4
  _parse_transport → TCP, ports 40000→80, tcp_flags=["PSH","ACK"], payload="GET /index…"
  detect_…         → payload khớp regex _HTTP_REQUEST → "HTTP"
  _parse_http      → method GET, target /index.html, version HTTP/1.1, headers{host:…}
  → event: {"application_protocol":"HTTP", "http_method":"GET", ..., "parse_status":"OK"}
```

---

## 4. Bản đồ file trong repo

```text
main.py                        Bắt packet (live/PCAP) + CLI + ghi log JSON Lines
parsers/
  __init__.py                  API công khai: parse_packet, error_event, validate_event
  errors.py                    2 lớp lỗi tự định nghĩa: IncompletePacket, UnsupportedProtocol
  pipeline.py                  LÕI: IPv4 → TCP/UDP → nhận diện → parse app → event
  schema.py                    "Hợp đồng" output: danh sách field, kiểm tra hợp lệ
TEST/
  TESTCASES.md                 Bảng map yêu cầu đề ↔ test ↔ kết quả thật
  mandatory_cases.py           Tạo packet cho 12 test case bắt buộc
  make_test_pcaps.py           Sinh lại pcap/ + output/ (bằng chứng)
  test_mandatory_cases.py      12 test §9 chạy qua CLI thật
  test_capture_cli.py          Test capture + CLI + PCAP
  test_pipeline.py             Test parser từng protocol (§3)
  test_nonstandard_ports.py    Test §4 (port không chuẩn)
  test_unknown_policy.py       Test §5 (mark/skip)
  test_event_schema.py         Test §6 (cấu trúc event)
  test_error_handling.py       Test §7 (không crash)
  test_jsonl_log.py            Test §8 (log JSON Lines)
  pcap/, output/               Bằng chứng đã sinh: capture + log
  *_results.txt                Kết quả chạy test đã lưu
docs/                          Đề bài PDF
Readme.md                      Tài liệu nộp bài (mục đích, cách chạy, AI disclosure)
knowledge.md                   File bạn đang đọc
```

**Thứ tự đọc code được đề xuất:** `main.py` (xem dữ liệu vào/ra) → `parsers/pipeline.py::parse_packet`
(xem 5 bước) → các hàm `_parse_*` (chi tiết từng protocol) → `parsers/schema.py` (output contract)
→ `TEST/test_mandatory_cases.py` (xem kết quả mong đợi).

---

## 5. Kiến thức mạng nền tảng

### 5.1 Mô hình phân lớp — vì sao phải "bóc" từng lớp

Một packet đi trên mạng là **các lớp lồng nhau** (encapsulation). Mỗi lớp có header riêng:

```text
┌───────────── Ethernet ─────────────┐  ← lớp 2: MAC address (đề KHÔNG yêu cầu)
│ ┌──────────── IPv4 ─────────────┐  │  ← lớp 3: IP address   (§3: Network Parser)
│ │ ┌────── TCP / UDP ────────┐   │  │  ← lớp 4: port         (§3: Transport Parser)
│ │ │   HTTP / DNS / SMTP     │   │  │  ← lớp 7: nội dung     (§3: App Parser)
│ │ └─────────────────────────┘   │  │
│ └───────────────────────────────┘  │
└────────────────────────────────────┘
```

**Analogy:** giống bóc nhiều lớp phong bì thư. Phải mở phong bì ngoài (Ethernet) mới thấy địa chỉ
nhà (IPv4), mở tiếp mới thấy số phòng (port), rồi mới đọc nội dung thư (HTTP/DNS/SMTP).
Code làm đúng việc đó: mỗi tầng chỉ bóc lớp của mình rồi chuyển payload lên tầng trên.

### 5.2 IPv4 header — các field code dùng

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
```

| Field | Nghĩa | Code kiểm tra gì |
|---|---|---|
| `version` | phải là 4 (IPv4) | khác 4 → `UNSUPPORTED` (IPv6 không thuộc phạm vi đề) |
| `ihl` | độ dài header tính theo **word 4 byte**, tối thiểu 5 (=20 byte) | `< 5` → `MALFORMED` |
| `len` (Total Length) | độ dài cả packet (header + payload) | Nếu payload thực tế **ngắn hơn** `len` dự tính → `INCOMPLETE` (packet bị cắt) |
| `proto` | giao thức tầng trên: 6 = TCP, 17 = UDP | dùng để báo `INCOMPLETE` khi thiếu header transport |
| `src`, `dst` | địa chỉ IP | đưa vào event |

**Tại sao `ihl` quan trọng?** Vì header IPv4 có thể dài hơn 20 byte (khi có options). Code tính
`header_words * 4` byte header rồi phần còn lại mới là payload.

### 5.3 TCP — cái gì code lấy ra và vì sao

| Field | Nghĩa | Trong event |
|---|---|---|
| `sport`, `dport` | port nguồn/đích | `src_port`, `dst_port` |
| `flags` | các cờ điều khiển | `tcp_flags` (list tên cờ) |
| `seq`, `ack` | số thứ tự / xác nhận (dùng để ghép luồng dữ liệu) | `tcp_sequence`, `tcp_acknowledgment` |
| `window` | kích thước cửa sổ nhận | `tcp_window` |
| `dataofs` | độ dài header TCP theo word 4 byte (như `ihl`) | kiểm tra `< 5` → `MALFORMED` |

**TCP 3-way handshake** (test case số 1 của đề):

```text
Client ── SYN (seq=x) ─────────────────► Server     tcp_flags = ["SYN"]
Client ◄─ SYN+ACK (seq=y, ack=x+1) ──── Server     tcp_flags = ["SYN","ACK"]
Client ── ACK (ack=y+1) ───────────────► Server     tcp_flags = ["ACK"]
```

**Bit của flags** (thứ tự trong code `_tcp_flags`):
`FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80`.
Code kiểm tra `flags & (1 << i)` — nghĩa là **dịch bit**, tương đương nhân 1,2,4,8…
Cờ PSH+ACK rất hay gặp khi có dữ liệu: `0x08 | 0x10 = 0x18`.

### 5.4 UDP — đơn giản hơn TCP

UDP chỉ có `sport`, `dport`, `len` (độ dài cả header 8 byte + payload). Không có flags, không
handshake, không đảm bảo. DNS thường đi trên UDP.

### 5.5 HTTP/1.x — cấu trúc văn bản

```text
GET /index.html HTTP/1.1        ← request line: METHOD  TARGET  VERSION
Host: example.test              ← header: Tên: Giá trị
User-Agent: idstest/1.0
                                ← dòng trống (CRLF CRLF) = hết header
(body nếu có)                   ← với POST, độ dài do Content-Length quyết định
```

Response:

```text
HTTP/1.1 200 OK                 ← status line: VERSION  STATUS_CODE  REASON
Server: ids-test
Content-Length: 15
                                ← dòng trống
<html>ok</html>                 ← body
```

Code dùng regex (`_HTTP_REQUEST`, `_HTTP_RESPONSE`) để nhận dạng **dòng đầu tiên**, rồi tách
header/body bằng `\r\n\r\n`. Đây chính là "payload-based detection" mà đề khuyến khích (§4).

### 5.6 DNS — cấu trúc nhị phân, không phải text

DNS là dữ liệu **binary**, nên không thể dùng regex. Header 12 byte:

```text
+---------------------+---------------------+
|        ID (16 bit)  |QR|Opcode|  … flags   |   QR=0 query, QR=1 response
+---------------------+---------------------+
| QDCOUNT | ANCOUNT  | NSCOUNT | ARCOUNT     |   số lượng record mỗi section
+---------------------+---------------------+
| Question…  (tên miền + QTYPE)              |   ví dụ: example.com  A
+--------------------------------------------+
| Answer…    (tên + TYPE + TTL + RDATA)      |   ví dụ: example.com A 300 93.184.216.34
+--------------------------------------------+
```

| Record type | Ý nghĩa |
|---|---|
| `A` | địa chỉ IPv4 |
| `AAAA` | địa chỉ IPv6 |
| `CNAME` | tên thay thế (alias) |
| `MX` | mail server |
| `TXT` | text tuỳ ý |
| `NS`, `SOA`, `PTR` | name server, thông tin vùng, reverse lookup |

**Hai điểm rất dễ bị hỏi:**

1. **DNS trên TCP có thêm 2 byte length prefix** ở đầu (vì TCP là stream, cần biết message dài bao
   nhiêu). Hàm `_dns_candidates()` xử lý việc này.
2. **Name compression**: trong DNS, tên miền lặp lại được nén bằng con trỏ. Scapy tự giải nén, nên
   code chỉ việc đọc `qname`/`rrname`.

### 5.7 SMTP — giao thức dòng lệnh

```text
Client →  EHLO mail.example.test        ← command (verb + tham số)
Server ←  250 2.1.0 Ok                  ← response: mã 3 chữ số + text
Client →  MAIL FROM:<alice@example.test>
Client →  RCPT TO:<bob@example.test>
```

Mã trả lời: `2xx` = thành công, `3xx` = chờ thêm, `4xx` = lỗi tạm, `5xx` = lỗi vĩnh viễn.
SMTP nhiều dòng dùng `250-` cho dòng giữa và `250 ` cho dòng cuối — code lấy dòng đầu tiên nên
vẫn đọc được mã.

### 5.8 JSON Lines — định dạng log của bài

```text
{"packet_id": 1, ...}      ← 1 dòng = 1 event hoàn chỉnh
{"packet_id": 2, ...}
```

| Ưu điểm | Vì sao quan trọng với IDS |
|---|---|
| Ghi kiểu **streaming**, không cần đóng mảng | Bắt packet liên tục, không biết trước khi nào dừng |
| 1 dòng hỏng không làm hỏng cả file | Nếu chương trình chết giữa chừng, phần đã ghi vẫn đọc được |
| Đọc lại dễ: `for line in f: json.loads(line)` | Bài sau chỉ cần đọc từng dòng để phân tích |
| Append được | Có thể ghi tiếp nhiều phiên capture |

---

## 6. Giải thích từng file / từng hàm

### 6.1 `main.py` — tầng capture + CLI + logging

#### `Capture_through_interface()` — §2.1.1 Live capture

```python
sniff(iface=interface, prn=packet_handler, count=count,
      timeout=timeout, filter=packet_filter, store=False)
```

| Tham số | Ý nghĩa |
|---|---|
| `iface` | card mạng cần bắt (`eth0`, `wlan0`…) |
| `prn` | **callback**: hàm được gọi cho **mỗi** packet → đưa packet vào pipeline |
| `count` | bắt bao nhiêu packet rồi dừng (`0` = không giới hạn) |
| `timeout` | dừng sau N giây |
| `filter` | BPF filter, ví dụ `"tcp or udp"` (lọc ngay trong kernel, đỡ tốn CPU) |
| `store=False` | **không lưu** packet vào RAM — quan trọng vì IDS chạy lâu, lưu hết sẽ tràn RAM |

> "Ghi nhận thời điểm packet được thu nhận": Scapy tự gán `packet.time` (epoch giây). Code chuyển
> thành ISO-8601 UTC trong field `timestamp`.

#### `_is_short_record()` và `Capture_through_pcap()` — §2.1.2 PCAP

```python
with PcapReader(pcap_file) as reader:
    while count == 0 or processed < count:
        try:
            packet = next(reader)          # (1)
        except StopIteration:
            break                          # (2) hết file → dừng êm
        except (OSError, Scapy_Exception, struct.error, ValueError) as error:
            packet_error_handler(...)      # (3) record hỏng → ghi log lỗi, dừng êm
            break
        processed += 1
        packet_handler(packet)             # (4) CÙNG callback với live capture
        if _is_short_record(packet, reader.snaplen):
            packet_error_handler("truncated PCAP packet …")   # (5)
```

Giải thích 5 bước:

1. `next(reader)` — Scapy đọc đúng 1 record và **giải mã (dissect)** thành packet.
2. Hết file bình thường → `StopIteration` → dừng, **không phải lỗi**. (Nếu dùng
   `reader.read_packet()` thì hết file cũng ném `EOFError`, dễ nhầm là file hỏng — xem mục 10.)
3. Record mà Scapy không giải mã nổi → báo lỗi qua handler rồi dừng. PCAP là stream tuần tự,
   mất đồng bộ thì **không thể đọc tiếp** — nên đây là hành vi đúng, không phải bỏ sót.
4. **Quan trọng nhất:** cùng một `packet_handler` với live capture ⇒ đề yêu cầu "không xây hai
   parser độc lập" được thoả mãn bằng thiết kế, không phải bằng lời hứa.
5. `_is_short_record`: nếu số byte **thực đọc được** nhỏ hơn `wirelen` trong khi `snaplen` cho phép
   độ dài đó ⇒ file bị cắt. Nếu file chỉ capture một phần theo snaplen (bình thường) thì không báo.

#### `_parse_safely()` — lưới an toàn thứ 2

```python
try:
    return parse_packet(packet, packet_id)
except Exception as error:                # bắt mọi lỗi bất ngờ
    return error_event(packet_id, f"parser failure contained: {error}")
```

Nếu trong parser có bug, chương trình **vẫn chạy** và event vẫn hợp lệ (chỉ khác là có `error`).

#### `PacketEventWriter` — class ghi log (§8)

```python
writer = PacketEventWriter(output, unknown_policy="mark")
writer(packet)          # __call__: packet_id += 1 → parse → ghi 1 dòng
writer.write_error(msg) # ghi 1 event lỗi (INCOMPLETE), luôn ghi kể cả policy=skip
writer.packet_id        # số packet đã xử lý
writer.written          # số dòng đã ghi (nhỏ hơn nếu skip)
```

`--unknown-policy skip` **không** bỏ qua event lỗi: log vẫn giữ lại để điều tra.

#### `main()` — CLI và exit code

| Tham số | Ý nghĩa |
|---|---|
| `--interface` / `--pcap` | chọn nguồn; **bắt buộc chọn đúng 1** (mutually exclusive, required) |
| `--count` | giới hạn số packet (0 = không giới hạn) |
| `--timeout` | dừng live capture sau N giây (chỉ dùng với `--interface`) |
| `--filter` | BPF filter (chỉ dùng với `--interface`) |
| `--output` | ghi ra file JSON Lines (không có thì in ra stdout) |
| `--unknown-policy` | `mark` (mặc định) hoặc `skip` |

Exit code: `0` thành công · `1` lỗi capture (thiếu quyền, sai interface…) · `130` người dùng Ctrl-C.
Kiểm tra tham số bằng `parser.error(...)` → argparse tự in hướng dẫn và thoát code `2`.

### 6.2 `parsers/pipeline.py` — lõi của bài

#### `parse_packet(packet, packet_id)` — 5 bước của đề

```python
event = { 15 field mặc định }        # luôn có đủ field, chưa biết gì thì để None/"UNKNOWN"
try:
    network   = _parse_ipv4(packet)                  # Bước 1: Network Parser
    transport = _parse_transport(network["payload"], packet)  # Bước 2: Transport Parser
    protocol  = detect_application_protocol(payload, src_port, dst_port, packet)  # Bước 3
    event.update(parse_application_payload(protocol, payload, packet))            # Bước 4
except UnsupportedProtocol as e:  event → "UNSUPPORTED"
except IncompletePacket  as e:    event → "INCOMPLETE"
except (ValueError, …)   as e:    event → "MALFORMED"
except Exception         as e:    event → "MALFORMED" (lưới cuối)
return _json_compatible(event)                                # Bước 5: JSON-safe
```

**Vì sao event khởi tạo đủ field trước?** Để **mọi event có cùng "hình dạng"** — bài sau chỉ cần
`event["application_protocol"]`, không phải `if "application_protocol" in event`. Đây là tinh thần §6.

#### `_parse_ipv4()` — tầng 1

| Việc làm | Kết quả nếu sai |
|---|---|
| Không có lớp IP (ARP, IPv6…) | `UnsupportedProtocol("IPv4 header is missing")` |
| `version != 4` | `UNSUPPORTED` |
| `ihl < 5` (header < 20 byte) | `MALFORMED` |
| `len < ihl*4` | `MALFORMED` |
| payload thực < `len - ihl*4` | `INCOMPLETE("truncated IPv4 payload")` |

**Chi tiết nhỏ nhưng hay bị hỏi:** `header_words = 5 if ip.ihl is None else int(ip.ihl)`. Scapy để
`ihl=None` với packet mới tạo trong bộ nhớ (chưa serialize). Nếu không xử lý, mọi test tự tạo packet
sẽ báo lỗi sai.

#### `_parse_transport()` — tầng 2

* **TCP:** kiểm tra `dataofs >= 5`; payload thực < header → `INCOMPLETE`; lấy
  `bytes(tcp.payload)` làm payload ứng dụng; lấy `sport/dport/flags/seq/ack/window`.
* **UDP:** `len < 8` → `MALFORMED`; payload thực < `udp.len` → `INCOMPLETE`; cắt payload đúng
  `udp.len - 8` byte (bỏ byte đệm).
* **Không phải TCP/UDP:** nếu `ip.proto` là 6/17 thì packet bị cắt phần transport → `INCOMPLETE`;
  còn lại (ICMP=1, …) → `UNSUPPORTED`.

#### `detect_application_protocol()` — tầng 3 (trái tim của §4 và §5)

Thứ tự kiểm tra (thứ tự này là **quyết định thiết kế**, không phải ngẫu nhiên):

```python
1. Scapy đã giải mã lớp DNS?            → "DNS"    (bằng chứng mạnh nhất)
2. Payload khớp _HTTP_REQUEST/_HTTP_RESPONSE → "HTTP"   (chữ ký text, port nào cũng đúng)
3. Payload khớp _SMTP_COMMAND/_SMTP_RESPONSE → "SMTP"
4. _looks_like_dns(payload)              → "DNS"    (kiểm tra cấu trúc, port nào cũng đúng)
5. Port thuộc nhóm HTTP + payload giống HTTP → "HTTP"   (kết hợp port + payload)
6. Port thuộc nhóm SMTP + payload giống SMTP → "SMTP"
7. Port 53/5353                          → "DNS"    (gợi ý port, sẽ báo MALFORMED nếu payload hỏng)
8. còn lại                               → "UNKNOWN"
```

Nhóm port: HTTP `80, 8080, 8000, 8008, 8888` · DNS `53, 5353` · SMTP `25, 465, 587, 2525`.

**Vì sao ưu tiên chữ ký payload trước port?** Vì port có thể bị đổi (HTTP 18080) hoặc bị dùng sai
(ai đó gửi binary tới port 80). Ngược lại, **vì sao vẫn còn bước 7 dùng port?** Vì DNS là binary nên
nếu packet DNS bị cắt hỏng, ta vẫn muốn ghi nhận "đây là DNS nhưng lỗi" (`DNS` + `MALFORMED`) thay
vì `UNKNOWN` — hữu ích hơn cho người điều tra.

#### Nhận diện DNS: 3 lớp kiểm tra chống "đoán bừa"

```python
def _decode_dns(payload):                    # 1. thử giải mã, chấp nhận TCP length prefix
    for candidate in _dns_candidates(payload):
        dns = DNS(candidate)
        if _dns_header_is_plausible(dns):    # 2. header phải "hợp lý"
            return dns
    return None

def _dns_header_is_plausible(dns):           # 3. các điều kiện
    opcode <= 5                              #    opcode hợp lệ
    0 <= mỗi count <= 100                    #    số record không vô lý
    có ít nhất 1 count > 0                   #    không phải toàn 0
    counts == số record Scapy giải mã được    #    QUAN TRỌNG NHẤT
```

**Vì sao cần điều kiện cuối?** Vì 12 byte đầu của *bất kỳ* payload nào cũng có thể bị đọc như header
DNS (ví dụ chuỗi `"GET /index.html…"` cho ra qdcount = 12137). Bắt buộc "số đếm trong header phải
khớp số record thật đọc được" khiến xác suất đoán bừa gần như bằng 0.

#### `_parse_http()` — tầng 4 (HTTP)

```text
Tách header/body tại \r\n\r\n (hoặc \n\n)
Dòng 1 → regex request  → http_message_type=request,  http_method, http_target, http_version
         regex response → http_message_type=response, status_code, reason_phrase
Các dòng sau → dict headers (tên header viết thường)
Phần còn lại → body (decode UTF-8, lỗi thì thay bằng ký tự thay thế — không crash)
```

#### `_parse_dns()` — tầng 4 (DNS)

Trả về: `dns_transaction_id` (ID), `dns_is_response` (bool), `dns_questions` (list), `dns_answers`
(list, mỗi phần tử có `name/type/ttl/data`). Nếu payload rỗng → `MALFORMED("empty DNS payload")`;
nếu không giải mã được → `MALFORMED("DNS decode failed")`.

`_dns_records(value, type)` là hàm phụ quan trọng: trong Scapy, `dns.qd` / `dns.an` là **list-field
đặc biệt**, không phải đối tượng `DNSQR`/`DNSRR` đơn lẻ → phải chuẩn hoá về `list` rồi lọc đúng kiểu.

#### `_parse_smtp()` — tầng 4 (SMTP)

Lấy dòng đầu tiên, thử khớp lệnh (`EHLO`, `MAIL FROM`, `RCPT TO`, …) trước, rồi tới mã trả lời:

```text
"smtp_message_type": "command"  → smtp_command, smtp_argument
"smtp_message_type": "response" → smtp_status_code, smtp_text
```

#### `_json_compatible()` — bảo đảm output luôn là JSON hợp lệ (§6)

JSON không có kiểu `bytes`, còn Scapy trả về nhiều thứ "lạ". Hàm này duyệt đệ quy:
`dict` → dict, `list/tuple` → list, `bytes` → chuỗi UTF-8 (nếu lỗi thì `{"base64": "..."}`),
kiểu cơ bản → giữ nguyên, còn lại → `str()`. Nhờ vậy `json.dumps(event)` **không bao giờ** lỗi.

#### `error_event()` — event cho thứ không parse được

Dùng khi capture gặp record hỏng, hoặc parser có lỗi bất ngờ. Vẫn đủ 15 field chuẩn + `error`, nên
log vẫn "đồng dạng" với các event khác.

### 6.3 `parsers/errors.py` — 2 lớp lỗi, vì sao cần

```python
class IncompletePacket(ValueError):    # "thiếu dữ liệu": gói bị cắt, cần thêm byte / cần ghép
class UnsupportedProtocol(ValueError): # "ngoài phạm vi": IPv6, ARP, ICMP… không thuộc đề
```

Cả hai kế thừa `ValueError` để vẫn được bắt bởi `except ValueError` ở nơi khác, nhưng cho phép
`parse_packet` **phân biệt** và gán `parse_status` khác nhau. Đây là ví dụ "dùng exception như một
phần của thiết kế", không phải chỉ để báo lỗi.

### 6.4 `parsers/schema.py` — hợp đồng output (§6)

* `COMMON_EVENT_FIELDS`: 15 field **luôn có** trong mọi event.
* `HTTP_EVENT_FIELDS`, `DNS_EVENT_FIELDS`, `SMTP_EVENT_FIELDS`, `ERROR_EVENT_FIELDS`: các field
  **tuỳ chọn**, chỉ xuất hiện khi đúng protocol đó.
* `ALLOWED_EVENT_FIELDS` = hợp của tất cả (dùng để phát hiện field lạ).
* Các "enum": `NETWORK_PROTOCOLS`, `TRANSPORT_PROTOCOLS`, `APPLICATION_PROTOCOLS`,
  `PARSE_STATUSES`, `TCP_FLAG_NAMES`.
* `validate_event(event) -> list[str]`: trả về **danh sách vấn đề**, rỗng nghĩa là hợp lệ.

`validate_event` kiểm tra: đủ field bắt buộc · không có field lạ · `packet_id` là số nguyên dương ·
`timestamp`/`src_ip`/`dst_ip` là chuỗi hoặc `null` · port là số 0–65535 hoặc `null` · các trường
enum nằm trong danh sách cho phép · `tcp_flags` là list tên cờ hợp lệ · `payload_length >= 0` ·
`json.dumps(event)` chạy được.

**Ý nghĩa:** đây là "test tự động cho cấu trúc" — bài sau có thể gọi `validate_event` để chắc chắn
input mình nhận đúng chuẩn.

### 6.5 `parsers/__init__.py` — API công khai

```python
from parsers import parse_packet, error_event, validate_event, COMMON_EVENT_FIELDS, …
```

Chỉ 3 hàm + vài hằng số được export: người dùng module không cần biết bên trong có bao nhiêu hàm phụ.
Đây gọi là **encapsulation** ở mức module.

### 6.6 `TEST/` — bộ test và bằng chứng

| File | Kiểm tra điều gì | Cách làm |
|---|---|---|
| `test_capture_cli.py` | CLI, live capture (mock), PCAP thật, JSON Lines | `patch("main.sniff")` để không cần mạng thật |
| `test_pipeline.py` | 13 test parse cơ bản | gọi trực tiếp `parse_packet` |
| `test_nonstandard_ports.py` | §4: HTTP 18080, DNS 53000, SMTP 2526, DNS/TCP | serialize rồi **kiểm tra Scapy không có lớp DNS** để chứng minh chỉ payload mới phát hiện được |
| `test_unknown_policy.py` | §5: `mark` vs `skip` | chạy CLI thật với 2 packet (1 UNKNOWN, 1 HTTP) |
| `test_event_schema.py` | §6: mọi event hợp lệ, JSON-safe | gọi `validate_event` |
| `test_error_handling.py` | §7: 6 loại input xấu | tạo packet/PCAP hỏng thật |
| `test_jsonl_log.py` | §8: 1 dòng/event, log cả lỗi | đọc file log sau khi chạy |
| `test_mandatory_cases.py` | §9: 12 test bắt buộc **qua CLI** | dùng packet từ `mandatory_cases.py` |
| `mandatory_cases.py` | "nguồn sự thật" tạo packet | cả test và script sinh bằng chứng dùng chung |
| `make_test_pcaps.py` | Sinh `pcap/` + `output/` để nộp | gọi `main.main()` thật |

**Kỹ thuật test đáng nhớ:**

* `patch("main.sniff")` — thay hàm thật bằng mock để test logic CLI mà không cần quyền root.
* `_FakePcapReader` — giả lập object đọc PCAP, có `__next__` ném `StopIteration` khi hết.
* Dùng `wrpcap()` để tạo PCAP thật → test đúng đường đi thật của Scapy.
* Load module cùng thư mục bằng `importlib` — tránh phụ thuộc `sys.path`.

---

## 7. Event chuẩn hoá gồm những gì

**15 field luôn có** (`COMMON_EVENT_FIELDS`):

| Field | Kiểu | Ý nghĩa |
|---|---|---|
| `packet_id` | int ≥ 1 | thứ tự packet (1, 2, 3…). `skip` làm **thiếu số** → biết packet nào bị bỏ |
| `timestamp` | string/null | thời điểm capture, ISO-8601 UTC |
| `src_ip`, `dst_ip` | string/null | địa chỉ IPv4 |
| `network_protocol` | `IPv4`/`UNKNOWN` | kết quả tầng 1 |
| `transport_protocol` | `TCP`/`UDP`/`UNKNOWN` | kết quả tầng 2 |
| `src_port`, `dst_port` | int/null | port |
| `tcp_flags` | list[str] | ví dụ `["SYN","ACK"]`; UDP thì `[]` |
| `tcp_sequence`, `tcp_acknowledgment`, `tcp_window` | int/null | field của TCP |
| `application_protocol` | `HTTP`/`DNS`/`SMTP`/`UNKNOWN` | kết quả tầng 3 |
| `payload_length` | int ≥ 0 | số byte payload tầng ứng dụng |
| `parse_status` | xem mục 8 | kết quả tổng thể |

**Field tuỳ chọn theo protocol:**

| Protocol | Field thêm vào |
|---|---|
| HTTP | `http_message_type`, `http_method`, `http_target`, `http_version`, `status_code`, `reason_phrase`, `headers`, `body` |
| DNS | `dns_transaction_id`, `dns_is_response`, `dns_questions`, `dns_answers` |
| SMTP | `smtp_message_type`, `smtp_command`, `smtp_argument`, `smtp_status_code`, `smtp_text` |
| Mọi event lỗi | `error` (mô tả ngắn vì sao) |

---

## 8. Phân loại lỗi

| `parse_status` | Nghĩa | Ví dụ |
|---|---|---|
| `OK` | parse xong bình thường | HTTP GET đọc được method/target |
| `UNSUPPORTED` | ngoài phạm vi đề (không phải lỗi dữ liệu) | ARP, IPv6, ICMP |
| `INCOMPLETE` | **thiếu dữ liệu**: packet bị cắt, cần thêm byte | payload thực ngắn hơn `ip.len`, PCAP record bị cắt |
| `MALFORMED` | dữ liệu **sai về mặt cấu trúc** | `ihl = 3`, header DNS không giải mã được |

Phân biệt `INCOMPLETE` vs `MALFORMED` rất hay được hỏi:
`INCOMPLETE` = "chưa đủ để hiểu" (có thể do capture cắt, không phải packet xấu) ·
`MALFORMED` = "đủ byte nhưng nội dung vô lý" (dấu hiệu packet bị sửa/giả mạo — chính là thứ IDS quan tâm).

---

## 9. Bảng quyết định thiết kế

| Vấn đề | Chọn | Vì sao | Thay thế đã cân nhắc |
|---|---|---|---|
| Dùng thư viện nào | **Scapy** | Đọc được cả live và PCAP, tự giải mã nhiều protocol, cài dễ | PyShark (cần tshark), raw socket (phải tự viết mọi header) |
| Cấu trúc event | **dict** | JSON-friendly, dễ in, dễ test | dataclass (gọn hơn nhưng cần convert khi dump JSON) |
| Tách parser riêng live/PCAP? | **Không** — 1 hàm `parse_packet` | Đề bắt buộc; tránh lệch hành vi | 2 parser (bị trừ điểm/loại) |
| Nhận diện protocol | **payload signature + port hint** | Đúng tinh thần §4/§5, chống false positive | chỉ port (sai khi service đổi port), chỉ payload (bỏ sót packet DNS hỏng) |
| DNS: kiểm tra cấu trúc | **counts phải khớp records** | Loại bỏ gần hết false positive | chỉ kiểm tra `len >= 12` (đoán bừa rất nhiều) |
| Lỗi parser | **exception có phân loại** | `parse_status` giàu thông tin, dễ debug | trả `None` (mất thông tin), để crash (vi phạm §7) |
| Đọc PCAP | **`PcapReader` + `next()`** | Phân biệt được "hết file" với "record hỏng" | `sniff(offline=…)` (im lặng khi file cắt), `read_packet()` (nhầm EOF) |
| Output mặc định | **stdout**, có `--output` để ghi file | Tiện thử nhanh, vẫn đủ yêu cầu §8 | luôn ghi file (khó thử), luôn stdout (không đủ §8 nếu không có option) |
| UNKNOWN | **`mark` mặc định, `skip` tuỳ chọn** | §5 cho phép cả hai; mặc định giữ dữ liệu để điều tra | chỉ mark / chỉ skip |
| An toàn khi parse | **3 lớp**: `try/except` trong `parse_packet`, `_parse_safely`, handler lỗi capture | Một packet lỗi không được giết tiến trình | chỉ 1 lớp |

---

## 10. Cái bẫy thực tế đã gặp

Đây là các lỗi **thật** đã gặp khi làm bài này — nhớ được thì vấn đáp rất dễ ghi điểm.

1. **Scapy để `ihl`/`dataofs` = `None`** với packet tạo trong bộ nhớ (chưa serialize) ⇒ nếu code
   viết `if ip.ihl < 5` sẽ lỗi `TypeError`. Cách xử lý: mặc định = 5.
2. **Callback trả về giá trị khác `None` thì Scapy in nó ra** ⇒ log bị nhân đôi mỗi event. Vì vậy
   `handle_packet()` và `PacketEventWriter.__call__()` **luôn trả `None`**.
3. **`dns.qd` / `dns.an` không phải một record đơn lẻ** mà là list-field đặc biệt. Duyệt kiểu
   `question = question.payload` sẽ sai ngay khi có nhiều record. Phải chuẩn hoá bằng `_dns_records`.
4. **Chỉ dựa vào port 53 là sai**: payload binary bất kỳ gửi tới port 53 đều bị gán nhãn DNS. Phải
   kiểm tra cấu trúc (counts khớp records).
5. **`PcapReader.read_packet()` ném `EOFError` cả khi hết file bình thường** — dễ tưởng là file hỏng
   và ghi log lỗi sai. Cách đúng: dùng `next(reader)` để hết file là `StopIteration`, còn lỗi thật
   là exception khác.
6. **`snaplen` vs `wirelen`**: nhiều file PCAP thật chỉ lưu một phần packet (snap length) — đó là
   bình thường. Chỉ coi là "file bị cắt" khi số byte đọc được < `wirelen` **và** `snaplen` đủ lớn.
7. **`sniff(offline=…)` khi file bị cắt thì im lặng**: nó trả về bình thường, không lỗi, nên nếu
   dùng `sniff` sẽ **không biết** file hỏng. Đổi sang `PcapReader` để ghi được event lỗi.
8. **DNS trên TCP có 2 byte length prefix** — nếu giải mã thẳng sẽ ra header sai. Phải thử cả
   payload gốc và payload đã bỏ 2 byte đầu.
9. **Test fixture bị lỗi do Scapy**: `IP()/UDP()/b""/DNS()` — lớp payload rỗng chen vào làm Scapy
   **không giải mã lớp DNS** sau khi serialize. Cách đúng: chỉ thêm `/Raw(load=…)` khi payload khác
   rỗng.
10. **`store=False` không phải chi tiết nhỏ**: bắt packet liên tục mà lưu hết vào RAM sẽ tràn bộ
    nhớ; cần xử lý kiểu streaming.
11. **`json.dumps` sẽ ném lỗi nếu event còn `bytes`** ⇒ mọi thứ phải đi qua `_json_compatible`.

---

## 11. Cheatsheet lệnh chạy

```bash
# ---------- cài đặt ----------
python -m pip install scapy

# ---------- chạy chương trình ----------
python main.py --interface eth0                        # live capture (cần quyền)
sudo python main.py --interface eth0 --count 10        # bắt 10 packet rồi dừng
sudo python main.py --interface eth0 --filter "tcp or udp" --timeout 30
python main.py --pcap test.pcap                        # đọc file PCAP
python main.py --pcap test.pcap --output events.jsonl  # ghi JSON Lines ra file
python main.py --pcap test.pcap --unknown-policy skip  # bỏ event UNKNOWN

# ---------- kiểm thử ----------
python -m unittest discover -s TEST -v                 # toàn bộ (79 test)
python -m unittest TEST.test_mandatory_cases -v        # 12 test bắt buộc §9
python TEST/make_test_pcaps.py                         # sinh lại pcap/ + output/

# ---------- xem kết quả ----------
python -m json.tool < events.jsonl | head              # đọc JSON cho dễ nhìn
```

**Xem nhanh output đẹp:**

```bash
python main.py --pcap TEST/pcap/http_get.pcap | python -m json.tool
```

---

## 12. Câu hỏi vấn đáp + trả lời ngắn

**A. Kiến trúc / thiết kế**

1. **Bài này làm gì trong hệ IDS?** — Bắt packet, parse, chuẩn hoá thành event JSON; là tầng đầu để
   các bài sau phát hiện tấn công mà không cần đọc raw packet.
2. **Vì sao live và PCAP dùng cùng pipeline?** — Đề bắt buộc; cùng một hàm `parse_packet` và cùng
   một callback nên hành vi giống hệt nhau, tránh code trùng.
3. **Vì sao output không được chứa raw packet?** — Để tách rời (decoupling): detection engine chỉ
   phụ thuộc vào cấu trúc event, đổi thư viện capture không phải sửa detection (§6).
4. **Vì sao dùng `dict` mà không dùng class?** — JSON-compatible trực tiếp, dễ serialize và dễ test.
5. **Làm sao biết event nào của protocol nào?** — Field `application_protocol` + các field đặc trưng
   (`http_*`, `dns_*`, `smtp_*`) và `validate_event` kiểm tra chúng.

**B. Nhận diện protocol (§4, §5)**

6. **Port có được dùng không?** — Có, nhưng chỉ là "gợi ý". Chữ ký payload là bằng chứng chính, nên
   HTTP ở 18080 hay DNS ở 53000 vẫn nhận đúng.
7. **Nhận diện HTTP bằng cách nào?** — Regex dòng đầu: `GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT`
   + `HTTP/1.x`, hoặc `HTTP/1.x <3 chữ số>` cho response.
8. **Nhận diện SMTP?** — Regex verb (`HELO/EHLO/MAIL FROM/RCPT TO/…`) hoặc dòng 3 chữ số.
9. **Nhận diện DNS khi không dùng port?** — Giải mã 12 byte header, yêu cầu opcode hợp lệ, mỗi count
   0–100, có ít nhất 1 count > 0, và **số count phải khớp số record đọc được**.
10. **Vì sao cần "counts khớp records"?** — Vì 12 byte đầu của bất kỳ payload nào cũng "trông giống"
    header DNS; điều kiện khớp giúp loại gần hết false positive.
11. **DNS trên TCP khác gì?** — Có 2 byte length prefix trước message (`_dns_candidates` bỏ nó).
12. **Packet UNKNOWN thì sao?** — Mặc định vẫn ghi event (`application_protocol: UNKNOWN`); có
    `--unknown-policy skip` để bỏ, nhưng **event lỗi vẫn luôn được ghi**.

**C. Giao thức (§3)**

13. **TCP handshake nhận biết thế nào?** — Qua `tcp_flags`: `["SYN"]`, `["SYN","ACK"]`, `["ACK"]`.
14. **Cờ TCP được tách bit thế nào?** — `flags & (1 << i)` với thứ tự FIN, SYN, RST, PSH, ACK, URG,
    ECE, CWR.
15. **`ihl` và `dataofs` là gì?** — Độ dài header IPv4/TCP tính theo word 4 byte; tối thiểu 5
    (20 byte). Nhỏ hơn 5 là không hợp lệ.
16. **Làm sao biết packet bị cắt?** — So sánh độ dài thực với `ip.len` (IPv4), `udp.len` (UDP),
    `dataofs` (TCP) → ném `IncompletePacket` → `INCOMPLETE`.
17. **HTTP POST body nằm ở đâu?** — Sau `\r\n\r\n`, độ dài theo `Content-Length`; code đọc hết phần còn
    lại của payload và decode UTF-8 (lỗi thì thay ký tự thay thế).
18. **DNS answer cần lấy gì?** — `name`, `type`, `ttl`, `data` (đề yêu cầu "ít nhất một answer").

**D. Lỗi và độ bền (§7)**

19. **Làm sao chương trình không crash?** — 3 lớp: `try/except` trong `parse_packet` (phân loại lỗi),
    `_parse_safely` (bắt mọi lỗi bất ngờ), và handler lỗi ở tầng capture (PCAP hỏng).
20. **`UNSUPPORTED` khác `INCOMPLETE` thế nào?** — `UNSUPPORTED` = protocol ngoài phạm vi đề (ICMP,
    ARP); `INCOMPLETE` = đúng protocol nhưng thiếu byte.
21. **`MALFORMED` khác `INCOMPLETE`?** — `MALFORMED` = đủ byte nhưng cấu trúc vô lý (dấu hiệu bị
    sửa/giả mạo) — đây là loại IDS quan tâm; `INCOMPLETE` thường do capture cắt.
22. **PCAP bị cắt xử lý ra sao?** — `PcapReader` + `next()`: hết file là `StopIteration` (bình
    thường); record hỏng thì ghi event `INCOMPLETE` rồi dừng êm, exit code `0`.
23. **Vì sao exit code 130?** — Quy ước shell cho Ctrl-C (`128 + SIGINT`).

**E. Logging & kiểm thử (§8, §9)**

24. **JSON Lines là gì, vì sao dùng?** — Mỗi dòng một JSON object; ghi kiểu streaming, file hỏng một
    dòng vẫn đọc được phần còn lại, dễ append.
25. **Log có ghi lỗi không?** — Có: truncated/unreadable PCAP, capture fail đều thành 1 dòng event
    (kể cả khi `--unknown-policy skip`).
26. **Test làm sao không cần mạng thật?** — Mock `sniff` cho live capture, dùng `wrpcap` tạo file
    PCAP thật cho phần parse.
27. **Vì sao có `validate_event`?** — Kiểm tra cấu trúc output tự động; bài sau dùng lại để chắc chắn
    input đúng chuẩn.
28. **Bằng chứng test nằm ở đâu?** — `TEST/pcap/` (capture), `TEST/output/` (log + summary),
    `TEST/TESTCASES.md` (bảng map yêu cầu ↔ test ↔ kết quả), `*_results.txt` (kết quả chạy).

---

## 13. Giới hạn hiện tại và hướng bài sau

**Chưa làm (và vì sao không sao):**

| Giới hạn | Ảnh hưởng | Bài sau cần gì |
|---|---|---|
| Không ghép TCP stream | HTTP request/response dài nhiều packet có thể chỉ đọc được phần đầu | Bộ đệm theo 4-tuple `(src_ip, src_port, dst_ip, dst_port)` + `seq` |
| Không ghép IP fragment | Packet bị phân mảnh không parse được payload | Dùng `fragment offset`/`MF` để ghép |
| Payload mã hoá (TLS) | Không đọc được nội dung HTTPS | Chỉ dùng metadata (SNI, JA3, kích thước, thời gian) |
| Chỉ IPv4 | IPv6 → `UNSUPPORTED` (đúng phạm vi đề) | Thêm parser IPv6 |
| Chưa phát hiện tấn công | Đây mới là tầng capture+parse | Signature (port scan, payload pattern) và/hoặc anomaly |

**Các field event sẽ dùng cho detection bài sau:**

| Phát hiện | Dựa vào |
|---|---|
| Port scan | `src_ip`, `dst_port` (nhiều port khác nhau trong thời gian ngắn), `tcp_flags` = `SYN` |
| SYN flood | đếm `tcp_flags` chứa `SYN` nhưng không có `ACK` hoàn tất |
| HTTP attack payload | `http_target`, `body`, `headers` |
| DNS tunneling | `dns_questions`, chiều dài `dns` name, tần suất |
| Spam / SMTP abuse | `smtp_command` (`MAIL FROM`/`RCPT TO`) + số lượng |
| Malformed/fuzz | `parse_status` = `MALFORMED` |

---

### Ghi chú cuối

* Tài liệu này giải thích **code thật trong repo** — hãy mở code đọc kèm để kiểm chứng, vì vấn đáp
  yêu cầu bạn *hiểu và giải thích được* mã nguồn mình nộp.
* Việc dùng AI đã được khai báo trong `Readme.md` (mục *AI assistance disclosure*) theo yêu cầu §10.
* Nếu bị hỏi "vì sao chỗ này làm thế?", ưu tiên trả lời bằng **lý do thiết kế** (mục 9) và **cái bẫy
  đã gặp** (mục 10) — đó là phần thể hiện bạn thực sự hiểu bài.
