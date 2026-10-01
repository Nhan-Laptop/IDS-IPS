"""Required decoder cases, using small events and original payloads."""

import unittest

from decoder import decode_event


class DecoderTests(unittest.TestCase):
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
