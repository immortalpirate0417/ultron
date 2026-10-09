from datetime import datetime, timedelta
from rules import detect_brute_force

BASE = datetime(2025, 1, 15, 2, 0, 0)


def failure(minute, ip="10.0.0.5", user="bob", event_id=None, status="FAILURE", etype="LOGIN"):
    return {
        "timestamp": BASE + timedelta(minutes=minute),
        "source_ip": ip, "username": user,
        "event_type": etype, "status": status, "event_id": event_id,
    }


def test_burst_is_detected():
    events = [failure(m, event_id=100 + m) for m in range(6)]
    result = detect_brute_force(events)
    assert len(result) == 1
    d = result[0]
    assert d["rule"] == "BRUTE_FORCE"
    assert d["source_ip"] == "10.0.0.5"
    assert d["failed_attempts"] == 6
    assert d["usernames"] == ["bob"]
    assert d["event_ids"] == [100, 101, 102, 103, 104, 105]
    assert d["first_seen"] == BASE
    assert d["last_seen"] == BASE + timedelta(minutes=5)


def test_below_threshold_not_detected():
    assert detect_brute_force([failure(m) for m in range(4)]) == []


def test_spread_out_failures_not_detected():
    events = [failure(m * 20) for m in range(6)]
    assert detect_brute_force(events) == []


def test_window_boundary_is_inclusive():
    events = [failure(m) for m in (0, 3, 6, 9, 10)]
    assert len(detect_brute_force(events)) == 1


def test_ips_are_separate():
    events = [failure(m, ip="10.0.0.5") for m in range(5)]
    events += [failure(m, ip="10.0.0.6") for m in range(5)]
    events += [failure(m, ip="10.0.0.7") for m in range(4)]
    result = detect_brute_force(events)
    assert {d["source_ip"] for d in result} == {"10.0.0.5", "10.0.0.6"}


def test_ignores_non_failures_and_missing_ip():
    events = [failure(m, status="SUCCESS") for m in range(6)]
    events += [failure(m, etype="FILE_ACCESS") for m in range(6)]
    events += [failure(m, ip=None) for m in range(6)]
    assert detect_brute_force(events) == []


def test_custom_threshold():
    events = [failure(m) for m in range(3)]
    assert len(detect_brute_force(events, threshold=3)) == 1


if __name__ == "__main__":
    test_burst_is_detected()
    test_below_threshold_not_detected()
    test_spread_out_failures_not_detected()
    test_window_boundary_is_inclusive()
    test_ips_are_separate()
    test_ignores_non_failures_and_missing_ip()
    test_custom_threshold()
    print("All rule tests passed.")