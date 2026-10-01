"""Required flow cases, using fixed timestamps instead of sleeps."""

import unittest

from flow_tracker import flow_snapshot, new_tracker, track_event
from TEST.common import sample_event


class FlowTests(unittest.TestCase):
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
