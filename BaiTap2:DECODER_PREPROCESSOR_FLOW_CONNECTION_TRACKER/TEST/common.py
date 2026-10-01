"""One ordinary event shared by the tests; each case changes only what it needs."""


def sample_event(reverse=False, **changes):
    event = {
        "packet_id": 1, "timestamp": 1700000000, "network_protocol": "IPv4",
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
        "transport_protocol": "TCP", "application_protocol": "UNKNOWN",
        "packet_length": 60, "payload_length": 0, "tcp_flags": [], "parse_status": "OK",
    }
    if reverse:
        event["src_ip"], event["dst_ip"] = event["dst_ip"], event["src_ip"]
        event["src_port"], event["dst_port"] = event["dst_port"], event["src_port"]
    event.update(changes)
    return event
