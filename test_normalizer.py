from normalizer import normalize_event, EVENT_FIELDS


def test_valid_record():
    raw = {
        "timestamp": "2025-01-15 02:30:00",
        "username": " alice ",
        "source_ip": "192.168.1.10",
        "destination_port": "22",
        "event_type": "login",
        "status": "failure",
        "severity": "high",
        "bytes_transferred": "1024",
    }
    event, err = normalize_event(raw)
    assert err is None
    assert set(event.keys()) == set(EVENT_FIELDS)
    assert event["username"] == "alice"
    assert event["event_type"] == "LOGIN"
    assert event["status"] == "FAILURE"
    assert event["severity"] == "HIGH"
    assert event["destination_port"] == 22
    assert event["bytes_transferred"] == 1024
    assert event["source_ip"] == "192.168.1.10"
    assert event["device_id"] is None


def test_invalid_values_become_none():
    raw = {
        "timestamp": "2025-01-15T02:30:00",
        "event_type": "LOGIN",
        "source_ip": "999.999.1.1",
        "source_port": "70000",
        "bytes_transferred": "-5",
        "severity": "bogus",
    }
    event, err = normalize_event(raw)
    assert err is None
    assert event["source_ip"] is None
    assert event["source_port"] is None
    assert event["bytes_transferred"] is None
    assert event["severity"] == "INFO"


def test_rejects_bad_records():
    assert normalize_event({"event_type": "LOGIN"})[0] is None
    assert normalize_event({"timestamp": "not a date", "event_type": "LOGIN"})[0] is None
    assert normalize_event({"timestamp": "2025-01-15 02:30:00"})[0] is None
    assert normalize_event("not a dict")[0] is None


if __name__ == "__main__":
    test_valid_record()
    test_invalid_values_become_none()
    test_rejects_bad_records()
    print("All normalizer tests passed.")