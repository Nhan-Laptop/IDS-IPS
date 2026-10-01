"""Decode representations without overwriting the original application fields."""

import base64
from email import policy
from email.parser import BytesParser
import quopri
from email.message import Message
import html
import re
from urllib.parse import parse_qsl, unquote, unquote_plus


def _bounded(value, max_size, problems):
    if len(value) > max_size:
        problems.append("decode size limit exceeded")
        return value[:max_size]
    return value


def _text(data, charset, problems):
    if isinstance(data, str):
        return data
    if not isinstance(data, bytes):
        problems.append("body must be text or bytes")
        return None
    try:
        return data.decode(charset)
    except UnicodeError:
        problems.append(f"invalid {charset} bytes")
        return data.decode(charset, errors="replace")
    except LookupError:
        problems.append(f"unsupported charset: {charset}")
        return data.decode("utf-8", errors="replace")


def _headers(value, problems):
    if value is None:
        return {}
    if not isinstance(value, dict):
        problems.append("headers must be a dictionary")
        return {}
    headers = {}
    for name, text in value.items():
        if not isinstance(name, str) or not isinstance(text, str):
            problems.append("header names and values must be text")
        else:
            headers[name.strip().lower()] = text.strip()
    return headers


def _percent(text, problems, form=False):
    if re.search(r"%(?![0-9a-fA-F]{2})", text):
        problems.append("invalid percent escape")
    decode = unquote_plus if form else unquote
    try:
        return decode(text, encoding="utf-8", errors="strict")
    except UnicodeError:
        problems.append("invalid UTF-8 in percent escapes")
        return decode(text, encoding="utf-8", errors="replace")


def _http(result, raw_payload, max_size, problems):
    headers = _headers(result.get("headers"), problems)
    content = Message()
    content["Content-Type"] = headers.get("content-type", "text/plain; charset=utf-8")
    target = result.get("http_target")
    if target is not None:
        if isinstance(target, str):
            target = _bounded(target, max_size, problems)
            result["decoded_http_target"] = _percent(target, problems)
        else:
            problems.append("http_target must be text")

    body = result.get("body")
    if raw_payload is not None:
        raw_payload = _bounded(raw_payload, max_size, problems)
        _, separator, body = raw_payload.partition(b"\r\n\r\n")
        if not separator:
            _, separator, body = raw_payload.partition(b"\n\n")
        if not separator:
            problems.append("incomplete HTTP headers")
            body = b""
    if body is None:
        return
    if not isinstance(body, (str, bytes)):
        problems.append("body must be text or bytes")
        return
    body = _bounded(body, max_size, problems)
    body = _text(body, content.get_content_charset() or "utf-8", problems)
    if content.get_content_type() == "application/x-www-form-urlencoded":
        result["decoded_body"] = _percent(body, problems, form=True)
        try:
            pairs = parse_qsl(body, keep_blank_values=True, encoding="utf-8", errors="strict")
        except UnicodeError:
            problems.append("invalid UTF-8 in form data")
            pairs = parse_qsl(body, keep_blank_values=True, errors="replace")
        result["decoded_form"] = [{"name": name, "value": value} for name, value in pairs]
    elif content.get_content_maintype() == "text" or content.get_content_type() == "application/xhtml+xml":
        result["decoded_body"] = html.unescape(body)
    else:
        result["decoded_body"] = body


def _transfer(data, encoding, problems):
    if encoding == "base64":
        try:
            return base64.b64decode(b"".join(data.split()), validate=True)
        except ValueError:
            problems.append("invalid MIME Base64")
            return data
    if encoding == "quoted-printable":
        if re.search(br"=(?![0-9a-fA-F]{2}|\r?\n)", data):
            problems.append("invalid MIME Quoted-Printable")
        return quopri.decodestring(data)
    if encoding not in ("", "7bit", "8bit", "binary"):
        problems.append(f"unsupported MIME encoding: {encoding}")
    return data


def _mime(result, raw_payload, max_size, problems):
    """Handle complete MIME messages or events with MIME headers and a body."""
    message = None
    if raw_payload:
        candidate = _bounded(raw_payload, max_size, problems)
        if candidate.upper().startswith(b"DATA\r\n"):
            candidate = candidate[6:]
        if candidate.endswith(b"\r\n.\r\n"):
            candidate = candidate[:-5]
            candidate = re.sub(br"(?m)^\.\.", b".", candidate)
        header_block = re.split(br"\r?\n\r?\n", candidate, maxsplit=1)[0]
        if re.search(br"(?im)^(content-type|content-transfer-encoding|mime-version):", header_block):
            message = BytesParser(policy=policy.default).parsebytes(candidate)
    headers = _headers(result.get("mime_headers", result.get("headers")), problems)
    if message is None:
        if not any(name in headers for name in ("content-type", "content-transfer-encoding", "mime-version")):
            return False
        body = result.get("body")
        if not isinstance(body, (str, bytes)):
            problems.append("MIME body missing or invalid")
            return True
        body = _bounded(body, max_size, problems)
        if isinstance(body, str):
            body = body.encode("utf-8")
        header_bytes = "\r\n".join(f"{name}: {value}" for name, value in headers.items()).encode("utf-8")
        message = BytesParser(policy=policy.default).parsebytes(header_bytes + b"\r\n\r\n" + body)

    result["mime_parts"] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_maintype() != "text":
            continue  # binary attachments are not character-decoded
        encoding = (part.get("Content-Transfer-Encoding") or "").strip().lower()
        charset = part.get_content_charset() or "utf-8"
        if encoding in ("base64", "quoted-printable"):
            encoded = part.get_payload().encode("ascii", errors="surrogateescape")
            data = _transfer(encoded, encoding, problems)
        else:
            data = part.get_payload(decode=True) or b""
            data = _transfer(data, encoding, problems)
        if part.defects:
            problems.append("malformed MIME part")
        text = _text(_bounded(data, max_size, problems), charset, problems)
        result["mime_parts"].append({"content_type": part.get_content_type(),
                                     "charset": charset, "transfer_encoding": encoding,
                                     "decoded_body": text})
    if not result["mime_parts"]:
        problems.append("no supported text MIME part")
    result["decoded_body"] = "\n".join(part["decoded_body"] for part in result["mime_parts"])
    if result.get("application_protocol", "UNKNOWN") == "UNKNOWN":
        result["application_protocol"] = "SMTP"
    return True


def decode_event(event, raw_payload=None, max_size=65536):
    """raw_payload is the original complete transport payload, when available."""
    if not isinstance(event, dict):
        return {"decode_status": "ERROR", "decode_reason": "event must be a dictionary"}
    result = dict(event)
    result.update(decoded_http_target=None, decoded_body=None, decoded_form=[])
    problems = []
    handled = False
    try:
        if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        if raw_payload is not None and not isinstance(raw_payload, bytes):
            raise ValueError("raw_payload must be bytes")
        protocol = result.get("application_protocol", "UNKNOWN")
        if isinstance(protocol, str) and protocol.strip().upper() == "HTTP":
            handled = True
            _http(result, raw_payload, max_size, problems)
        elif isinstance(protocol, str) and protocol.strip().upper() in ("SMTP", "UNKNOWN"):
            handled = _mime(result, raw_payload, max_size, problems)
    except Exception as error:
        problems.append(f"decode failed: {error}")
    result["decode_status"] = "PARTIAL" if problems else ("OK" if handled else "SKIPPED")
    result["decode_reason"] = "; ".join(problems) or None
    return result
