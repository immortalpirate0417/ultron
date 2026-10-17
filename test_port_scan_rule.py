from datetime import datetime, timedelta
from rules import detect_port_scan

BASE = datetime(2025, 1, 12, 23, 50, 0)


def conn(sec, port, src="192.168.50.55", dst="192.168.1.5",
         etype="NETWORK_CONNECTION", event_id=None):
    return {
        "timestamp": BASE + timedelta(seconds=sec),
        "source_ip": src, "destination_ip": dst, "destination_port": port,
        "event_type": etype, "event_id": event_id,
    }


def test_scan_is_detected():
    events = [conn(s, 20 + s, event_id=100 + s) for s in range(12)]
    result = detect_port_scan(events)
    assert len(result) == 1
    d = result[0]
    assert d["rule"] == "PORT_SCAN"
    assert d["source_ip"] == "192.168.50.55"
    assert d["destination_ip"] == "192.168.1.5"
    assert d["distinct_ports"] == 12
    assert d["ports"] == list(range(20, 32))
    assert d["event_ids"] == list(range(100, 112))
    assert d["first_seen"] == BASE
    assert d["last_seen"] == BASE + timedelta(seconds=11)
    assert d["severity"] == "MEDIUM"


def test_same_port_repeated_not_flagged():
    assert detect_port_scan([conn(s, 22) for s in range(20)]) == []


def test_below_threshold_not_flagged():
    assert detect_port_scan([conn(s, 20 + s) for s in range(9)]) == []


def test_spread_out_connections_not_flagged():
    events = [conn(s * 30, 20 + s) for s in range(12)]  # at most 5 inside any 120 s
    assert detect_port_scan(events) == []


def test_window_boundary_is_inclusive():
    seconds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 120]
    inside = [conn(s, 100 + i) for i, s in enumerate(seconds)]
    assert len(detect_port_scan(inside)) == 1
    seconds[-1] = 121
    outside = [conn(s, 100 + i) for i, s in enumerate(seconds)]
    assert detect_port_scan(outside) == []


def test_destinations_are_separate():
    events = [conn(s, 100 + s, dst="192.168.1.5") for s in range(10)]
    events += [conn(s, 200 + s, dst="192.168.1.6") for s in range(10)]
    events += [conn(s, 300 + s, dst="192.168.1.7") for s in range(6)]
    events += [conn(s, 400 + s, dst="192.168.1.8") for s in range(6)]
    result = detect_port_scan(events)
    assert {d["destination_ip"] for d in result} == {"192.168.1.5", "192.168.1.6"}


def test_ignores_other_events_and_missing_fields():
    events = [conn(s, 20 + s, etype="LOGIN") for s in range(12)]
    events += [conn(s, None) for s in range(12)]
    events += [conn(s, 20 + s, dst=None) for s in range(12)]
    events += [conn(s, 20 + s, src=None) for s in range(12)]
    assert detect_port_scan(events) == []


def test_custom_threshold():
    events = [conn(s, 20 + s) for s in range(5)]
    assert len(detect_port_scan(events, port_threshold=5)) == 1


if __name__ == "__main__":
    test_scan_is_detected()
    test_same_port_repeated_not_flagged()
    test_below_threshold_not_flagged()
    test_spread_out_connections_not_flagged()
    test_window_boundary_is_inclusive()
    test_destinations_are_separate()
    test_ignores_other_events_and_missing_fields()
    test_custom_threshold()
    print("All port scan rule tests passed.")