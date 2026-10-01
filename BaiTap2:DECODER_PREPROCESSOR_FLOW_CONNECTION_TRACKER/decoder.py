"""Decode representations without overwriting the original application fields."""

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
    except Exception as error:
        problems.append(f"decode failed: {error}")
    result["decode_status"] = "PARTIAL" if problems else ("OK" if handled else "SKIPPED")
    result["decode_reason"] = "; ".join(problems) or None
    return result
