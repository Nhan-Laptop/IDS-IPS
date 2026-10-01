"""A dictionary of active bidirectional flows. No TCP stream reassembly."""

from copy import deepcopy
import math

from preprocessor import parse_timestamp, preprocess_event


def new_tracker(tcp_timeout=120, udp_timeout=30):
    for value in (tcp_timeout, udp_timeout):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError("flow timeouts must be finite positive numbers")
    return {"active_flows": {}, "next_id": 1, "tcp_timeout": tcp_timeout, "udp_timeout": udp_timeout}


def flow_snapshot(flow):
    """Private bookkeeping does not belong in the JSON summary."""
    return deepcopy({name: value for name, value in flow.items() if not name.startswith("_")})


def _new_flow(tracker, event, now):
    flow = {
        "flow_id": f"flow_{tracker['next_id']}",
        "protocol": event["transport_protocol"], "application_protocol": event["application_protocol"],
        "endpoint_a": {"ip": event["src_ip"], "port": event["src_port"]},
        "endpoint_b": {"ip": event["dst_ip"], "port": event["dst_port"]},
        "start_time": event["timestamp"], "last_seen": event["timestamp"], "duration": 0,
        "packet_count": 0, "byte_count": 0,
        "forward_packet_count": 0, "backward_packet_count": 0,
        "forward_byte_count": 0, "backward_byte_count": 0,
        "SYN_count": 0, "ACK_count": 0, "FIN_count": 0, "RST_count": 0,
        "state": "NEW" if event["transport_protocol"] == "TCP" else "ACTIVE",
        "_start_seconds": now, "_last_seconds": now,
        "_syn_direction": None, "_synack_seen": False,
    }
    tracker["next_id"] += 1
    return flow


def _tcp_handshake(flow, event, direction):
    flags = event["tcp_flags"]
    if flow["state"] not in ("NEW", "HANDSHAKE"):
        return
    if "SYN" in flags and "ACK" not in flags:
        if flow["_syn_direction"] is None:
            flow["_syn_direction"] = direction
        flow["state"] = "HANDSHAKE"
    elif "SYN" in flags and "ACK" in flags:
        if flow["_syn_direction"] is not None and direction != flow["_syn_direction"]:
            flow["_synack_seen"] = True
            flow["state"] = "HANDSHAKE"
    elif "ACK" in flags and flow["_synack_seen"] and direction == flow["_syn_direction"]:
        flow["state"] = "ESTABLISHED"


def track_event(tracker, event):
    """Return (enriched event, completed summaries). Invalid events never create flows."""
    policy = "skip" if isinstance(event, dict) and event.get("processing_action") == "skip" else "mark"
    result = preprocess_event(event, policy)
    result.update(flow_id=None, direction=None, flow_state=None, track_status="SKIPPED")
    if not result["trackable"]:
        return result, []
    now = parse_timestamp(result["timestamp"]).timestamp()
    key = (result["src_ip"], result["dst_ip"], result["src_port"], result["dst_port"], result["transport_protocol"])
    reverse = (key[1], key[0], key[3], key[2], key[4])
    active = tracker["active_flows"]
    if key in active:
        flow = active[key]
        direction = "forward"
    elif reverse in active:
        flow = active[reverse]
        direction = "backward"
    else:
        flow = _new_flow(tracker, result, now)
        active[key] = flow
        direction = "forward"

    if now < flow["_start_seconds"]:
        flow["_start_seconds"] = now
        flow["start_time"] = result["timestamp"]
    if now > flow["_last_seconds"]:
        flow["_last_seconds"] = now
        flow["last_seen"] = result["timestamp"]
    flow["duration"] = flow["_last_seconds"] - flow["_start_seconds"]
    flow["packet_count"] += 1
    flow["byte_count"] += result["packet_length"]
    flow[f"{direction}_packet_count"] += 1
    flow[f"{direction}_byte_count"] += result["packet_length"]
    if flow["application_protocol"] == "UNKNOWN" and result["application_protocol"] != "UNKNOWN":
        flow["application_protocol"] = result["application_protocol"]
    if flow["protocol"] == "TCP":
        for flag in ("SYN", "ACK", "FIN", "RST"):
            if flag in result["tcp_flags"]:
                flow[f"{flag}_count"] += 1
        _tcp_handshake(flow, result, direction)
    result.update(flow_id=flow["flow_id"], direction=direction, flow_state=flow["state"], track_status="OK")
    return result, []
