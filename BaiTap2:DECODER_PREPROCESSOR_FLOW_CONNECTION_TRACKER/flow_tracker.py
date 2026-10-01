"""A dictionary of active bidirectional flows. No TCP stream reassembly."""

from copy import deepcopy
import math

from preprocessor import parse_timestamp, preprocess_event


def new_tracker(tcp_timeout=120, udp_timeout=30):
    for value in (tcp_timeout, udp_timeout):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError("flow timeouts must be finite positive numbers")
    return {"active_flows": {}, "next_id": 1, "tcp_timeout": tcp_timeout,
            "udp_timeout": udp_timeout, "_clock": None}


def flow_snapshot(flow):
    """Private bookkeeping does not belong in the JSON summary."""
    return deepcopy({name: value for name, value in flow.items() if not name.startswith("_")})


def expire_flows(tracker, now):
    """A PCAP uses capture time, not the speed at which the file is read."""
    try:
        clock = parse_timestamp(now).timestamp()
    except (TypeError, ValueError, OverflowError, OSError):
        return []
    tracker["_clock"] = max(clock, tracker["_clock"]) if tracker["_clock"] is not None else clock
    completed = []
    for key, flow in list(tracker["active_flows"].items()):
        timeout = tracker["tcp_timeout"] if flow["protocol"] == "TCP" else tracker["udp_timeout"]
        if tracker["_clock"] - flow["_last_seconds"] >= timeout:
            flow["state"] = "CLOSED"
            flow["close_reason"] = "idle_timeout"
            completed.append(flow_snapshot(flow))
            del tracker["active_flows"][key]
    return completed


def finish_flows(tracker, reason="eof"):
    completed = []
    for flow in tracker["active_flows"].values():
        flow["close_reason"] = reason
        completed.append(flow_snapshot(flow))
    tracker["active_flows"].clear()
    return completed


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
        "_fin_seen": {"forward": False, "backward": False},
        "_fin_acked": {"forward": False, "backward": False},
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


def _tcp_close(flow, event, direction):
    flags = event["tcp_flags"]
    if "RST" in flags:
        flow["state"] = "RESET"
        return "tcp_rst"
    other = "backward" if direction == "forward" else "forward"
    if "ACK" in flags and flow["_fin_seen"][other]:
        flow["_fin_acked"][other] = True
    if "FIN" in flags:
        flow["_fin_seen"][direction] = True
        flow["state"] = "CLOSING"
    if all(flow["_fin_seen"].values()) and all(flow["_fin_acked"].values()):
        flow["state"] = "CLOSED"
        return "tcp_fin"
    return None


def track_event(tracker, event):
    """Return (enriched event, completed summaries). Invalid events never create flows."""
    policy = "skip" if isinstance(event, dict) and event.get("processing_action") == "skip" else "mark"
    result = preprocess_event(event, policy)
    result.update(flow_id=None, direction=None, flow_state=None, track_status="SKIPPED")
    completed = expire_flows(tracker, result["timestamp"])
    if not result["trackable"]:
        return result, completed
    now = parse_timestamp(result["timestamp"]).timestamp()
    key = (result["src_ip"], result["dst_ip"], result["src_port"], result["dst_port"], result["transport_protocol"])
    reverse = (key[1], key[0], key[3], key[2], key[4])
    active = tracker["active_flows"]
    flow_key = reverse if key not in active and reverse in active else key
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
    close_reason = None
    if flow["protocol"] == "TCP":
        for flag in ("SYN", "ACK", "FIN", "RST"):
            if flag in result["tcp_flags"]:
                flow[f"{flag}_count"] += 1
        _tcp_handshake(flow, result, direction)
        close_reason = _tcp_close(flow, result, direction)
    result.update(flow_id=flow["flow_id"], direction=direction, flow_state=flow["state"], track_status="OK")
    if close_reason:
        flow["close_reason"] = close_reason
        completed.append(flow_snapshot(flow))
        del active[flow_key]
    return result, completed
