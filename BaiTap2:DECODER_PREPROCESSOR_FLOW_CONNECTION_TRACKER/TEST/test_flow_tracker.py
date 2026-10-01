"""Required flow cases, using fixed timestamps instead of sleeps."""

import unittest

from flow_tracker import flow_snapshot, new_tracker, track_event
from TEST.common import sample_event


class FlowTests(unittest.TestCase):
    def test_T07_tcp_handshake(self):
        tracker = new_tracker()
        inputs = [sample_event(tcp_flags=["SYN"]),
                  sample_event(reverse=True, tcp_flags=["SYN", "ACK"], timestamp=1700000001),
                  sample_event(tcp_flags=["ACK"], timestamp=1700000002)]
        results = [track_event(tracker, event)[0] for event in inputs]
        self.assertEqual(len({event["flow_id"] for event in results}), 1)
        self.assertEqual([event["flow_state"] for event in results], ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"])
        flow = flow_snapshot(next(iter(tracker["active_flows"].values())))
        self.assertEqual(flow["packet_count"], 3)
        self.assertEqual(flow["SYN_count"], 2)
        self.assertEqual(flow["ACK_count"], 2)
        self.assertEqual(flow["state"], "ESTABLISHED")
        self.assertEqual(flow["application_protocol"], "UNKNOWN")
        # An isolated ACK, a retransmitted SYN, or a wrong-direction ACK is not a handshake.
        other = new_tracker()
        self.assertEqual(track_event(other, sample_event(tcp_flags=["ACK"]))[0]["flow_state"], "NEW")
        track_event(other, sample_event(tcp_flags=["SYN"]))
        track_event(other, sample_event(tcp_flags=["SYN"]))
        track_event(other, sample_event(reverse=True, tcp_flags=["SYN", "ACK"]))
        wrong, _ = track_event(other, sample_event(reverse=True, tcp_flags=["ACK"]))
        self.assertEqual(wrong["flow_state"], "HANDSHAKE")
        self.assertEqual(track_event(other, sample_event(tcp_flags=["ACK"]))[0]["flow_state"], "ESTABLISHED")

    def test_T11_concurrent_flows(self):
        tracker = new_tracker()
        inputs = [sample_event(), sample_event(src_port=40001),
                  sample_event(dst_ip="10.0.0.3"), sample_event(transport_protocol="UDP")]
        results = [track_event(tracker, event)[0] for event in inputs]
        self.assertEqual(len({event["flow_id"] for event in results}), 4)
        self.assertEqual(len(tracker["active_flows"]), 4)
        response, _ = track_event(tracker, sample_event(reverse=True))
        self.assertEqual(response["flow_id"], results[0]["flow_id"])
        self.assertEqual(len(tracker["active_flows"]), 4)
        counts = sorted(flow["packet_count"] for flow in tracker["active_flows"].values())
        self.assertEqual(counts, [1, 1, 1, 2])

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
