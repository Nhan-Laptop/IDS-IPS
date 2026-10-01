"""Required decoder cases, using small events and original payloads."""

import unittest

from decoder import decode_event


class DecoderTests(unittest.TestCase):
    def test_T03_mime_base64_and_qp(self):
        for encoding, body, expected in [
                ("base64", "SGVsbG8=", "Hello"),
                ("quoted-printable", "Xin ch=C3=A0o", "Xin chào")]:
            with self.subTest(encoding=encoding):
                event = {"application_protocol": "SMTP", "body": body,
                         "headers": {"Content-Type": "text/plain; charset=utf-8",
                                     "Content-Transfer-Encoding": encoding}}
                result = decode_event(event)
                self.assertEqual(result["decoded_body"], expected)
                self.assertEqual(result["decode_status"], "OK")
                self.assertEqual(result["body"], body)
        raw = (b"DATA\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=ascii\r\n"
               b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n.\r\n")
        result = decode_event({"application_protocol": "UNKNOWN"}, raw)
        self.assertEqual(result["decoded_body"], "Hello")
        self.assertEqual(result["application_protocol"], "SMTP")
        self.assertEqual(result["decode_status"], "OK")
        no_header = decode_event({"application_protocol": "SMTP", "body": "SGVsbG8="})
        self.assertEqual(no_header["decode_status"], "SKIPPED")
        self.assertIsNone(no_header["decoded_body"])
        multipart = (b'Content-Type: multipart/alternative; boundary="part"\r\n\r\n'
                     b'--part\r\nContent-Type: text/plain\r\n'
                     b'Content-Transfer-Encoding: base64\r\n\r\nSGk=\r\n'
                     b'--part\r\nContent-Type: text/html\r\n'
                     b'Content-Transfer-Encoding: quoted-printable\r\n\r\n<b>Hi</b>\r\n'
                     b'--part--\r\n')
        result = decode_event({"application_protocol": "SMTP"}, multipart)
        self.assertEqual([part["decoded_body"] for part in result["mime_parts"]], ["Hi", "<b>Hi</b>"])
        self.assertEqual(result["decode_status"], "OK")

    def test_T02_html_entities(self):
        event = {"application_protocol": "HTTP", "headers": {"Content-Type": "text/html"},
                 "body": "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;"}
        result = decode_event(event)
        self.assertEqual(result["decoded_body"], '<script>alert("x")</script> & \u0027')
        self.assertEqual(result["body"], event["body"])
        self.assertEqual(result["decode_status"], "OK")
        not_html = dict(event, headers={"Content-Type": "application/json"})
        self.assertEqual(decode_event(not_html)["decoded_body"], event["body"])
        nested = dict(event, body="&amp;lt;script&amp;gt;")
        self.assertEqual(decode_event(nested)["decoded_body"], "&lt;script&gt;")
        self.assertEqual(decode_event(dict(event, body="&unknown;"))["decode_status"], "OK")

    def test_T01_url_decoding(self):
        raw = "/Search?q=%27%20OR%201%3D1&path=a+b&once=%2527"
        event = {"application_protocol": "HTTP", "http_target": raw,
                 "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                 "body": "name=Alice+Smith&literal=%2B&value=a%26b&blank="}
        result = decode_event(event)
        self.assertEqual(result["http_target"], raw)
        self.assertEqual(event["http_target"], raw)
        self.assertEqual(result["decoded_http_target"], "/Search?q=' OR 1=1&path=a+b&once=%27")
        self.assertEqual(result["body"], event["body"])
        self.assertEqual(result["decoded_form"], [
            {"name": "name", "value": "Alice Smith"}, {"name": "literal", "value": "+"},
            {"name": "value", "value": "a&b"}, {"name": "blank", "value": ""}])
        self.assertEqual(result["decode_status"], "OK")
        bad = decode_event({"application_protocol": "HTTP", "http_target": "/%GG/%"})
        self.assertEqual(bad["decode_status"], "PARTIAL")
        self.assertIn("percent", bad["decode_reason"])
        limited = decode_event(event, max_size=8)
        self.assertEqual(limited["decode_status"], "PARTIAL")
        self.assertEqual(limited["http_target"], raw)


if __name__ == "__main__":
    unittest.main()
