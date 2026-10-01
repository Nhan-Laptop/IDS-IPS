"""Required flow cases, using fixed timestamps instead of sleeps."""

import unittest

from flow_tracker import flow_snapshot, new_tracker, track_event
from TEST.common import sample_event


class FlowTests(unittest.TestCase):
    def test_T10_udp_dns_query_response(self):
        from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
        from main import packet_to_event
        query = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=53) / DNS(
            id=123, qd=DNSQR(qname="EXAMPLE.COM."))
        response = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=40000) / DNS(
            id=123, qr=1, qd=DNSQR(qname="EXAMPLE.COM."),
            an=DNSRR(rrname="EXAMPLE.COM.", type="A", rdata="93.184.216.34"))
        query.time = 1700000000
        response.time = 1700000001
        tracker = new_tracker()
        first, _ = track_event(tracker, packet_to_event(query, 1)[0])
        second, _ = track_event(tracker, packet_to_event(response, 2)[0])
        self.assertEqual(first["flow_id"], second["flow_id"])
        self.assertEqual(second["direction"], "backward")
        flow = flow_snapshot(next(iter(tracker["active_flows"].values())))
        self.assertEqual(flow["protocol"], "UDP")
        self.assertEqual(flow["application_protocol"], "DNS")
        self.assertEqual(flow["state"], "ACTIVE")
        self.assertEqual(flow["packet_count"], 2)
        self.assertEqual(flow["byte_count"], len(bytes(query)) + len(bytes(response)))
        self.assertEqual(flow["forward_byte_count"], len(bytes(query)))
        self.assertEqual(flow["backward_byte_count"], len(bytes(response)))
        self.assertEqual(flow["duration"], 1)
        self.assertEqual(flow["SYN_count"], 0)

    def test_T08_bidirectional_flow(self):
        tracker = new_tracker()
        forward, _ = track_event(tracker, sample_event())
        backward, _ = track_event(tracker, sample_event(reverse=True))
        again, _ = track_event(tracker, sample_event())
        self.assertEqual(forward["flow_id"], backward["flow_id"])
        self.assertEqual(again["flow_id"], forward["flow_id"])
        self.assertEqual([forward["direction"], backward["direction"], again["direction"]],
                         ["forward", "backward", "forward"])
        self.assertEqual(len(tracker["active_flows"]), 1)
        flow = flow_snapshot(next(iter(tracker["active_flows"].values())))
        self.assertEqual(flow["endpoint_a"], {"ip": "10.0.0.1", "port": 40000})
        self.assertEqual(flow["endpoint_b"], {"ip": "10.0.0.2", "port": 80})
        self.assertEqual(flow["forward_packet_count"], 2)
        self.assertEqual(flow["backward_packet_count"], 1)
        bad, _ = track_event(tracker, sample_event(dst_ip=None))
        self.assertIsNone(bad["flow_id"])
        self.assertEqual(bad["track_status"], "SKIPPED")
        self.assertEqual(flow["packet_count"], 3)
        self.assertEqual(len(tracker["active_flows"]), 1)


if __name__ == "__main__":
    unittest.main()
