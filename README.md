# NT204.R11.ANTN — Nguyễn Trọng Nhân (24521236)

| | |
|---|---|
| Course | NT204 — Hệ thống tìm kiếm, phát hiện và ngăn ngừa xâm nhập (IDS/IPS) |
| Class code (mã lớp) | NT204.R11.ANTN |
| Student (họ & tên) | Nguyễn Trọng Nhân |
| Student ID (MSSV) | 24521236 |
| Repository | <https://github.com/Nhan-Laptop/NT204.R11.ANTN_Nguyen-Trong-Nhan_24521236> |

This is the one GitHub repository used for the whole NT204 assignment. The code
is on the `main` branch, which is the default branch, and the repository is
public.

| Folder | Phase | Documentation |
|---|---|---|
| `BaiTap1:Packet_CAPTURER_AND_PARSER/` | Bài tập 1 — Packet Capture & Parser | `Readme.md`, `knowledge.md`, `TEST/TESTCASES.md` |
| `BaiTap2:DECODER_PREPROCESSOR_FLOW_CONNECTION_TRACKER/` | Bài tập 2 — Decoder, Preprocessor & Flow/Connection Tracker | `README.md`, `plan.md`, `TEST/TESTCASES.md` |

Homework 2 builds on Homework 1:

```text
Packet Capture & Parser → Decoder → Preprocessor → Flow/Connection Tracker
```

Homework 1 is not modified by the second phase; Homework 2 imports its
`parsers.parse_packet()` and continues from the events it produces.

## How to run the tests

```bash
# Bài tập 1
cd "BaiTap1:Packet_CAPTURER_AND_PARSER"
python -m unittest discover -s TEST -v

# Bài tập 2
cd "BaiTap2:DECODER_PREPROCESSOR_FLOW_CONNECTION_TRACKER"
python -m unittest discover -s TEST -v
```

The runtime dependency of both phases is Scapy:

```bash
python -m pip install scapy
```

Each phase keeps its recorded test evidence inside its own `TEST/` folder, as
the assignment requires. Git history contains one commit per small task and one
commit per test case.

## AI assistance disclosure

AI tool used: **OpenAI ChatGPT through the pi coding agent**.

Purpose of use:

- Discuss the design of the capture, parsing, decoding, preprocessing and flow
  tracking modules.
- Assist with writing the Scapy-based code and the test cases.
- Suggest the structure of the README and study notes.

The code, results and documentation were reviewed, run and adjusted by the
student, who is responsible for being able to explain all submitted source code.
