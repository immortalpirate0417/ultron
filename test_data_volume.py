from datetime import datetime, timedelta
from anomaly_stats import detect_unusual_data_volume

START = datetime(2025, 1, 6, 10, 0, 0)


def transfer(n, size, user="alice", etype="FILE_ACCESS", event_id=None, ip="192.168.1.10"):
    return {
        "timestamp": START + timedelta(minutes=n),
        "username": user, "source_ip": ip, "event_type": etype,
        "bytes_transferred": size, "resource": "/data/finance.csv",
        "event_id": event_id,
    }


def normal_history(user="alice", count=6, size=20000):
    return [transfer(n, size, user=user, event_id=n + 1) for n in range(count)]


def test_large_transfer_is_flagged():
    events = normal_history() + [transfer(50, 500000, event_id=99, ip="192.168.50.99")]
    result = detect_unusual_data_volume(events)
    assert len(result) == 1
    d = result[0]
    assert d["rule"] == "UNUSUAL_DATA_VOLUME"
    assert d["username"] == "alice"
    assert d["event_id"] == 99
    assert d["source_ip"] == "192.168.50.99"
    assert d["bytes_transferred"] == 500000
    assert d["baseline_mean_bytes"] == 20000.0
    assert d["baseline_std_bytes"] == 2000.0
    assert d["z_score"] == 240.0


def test_normal_transfers_not_flagged():
    events = normal_history() + [transfer(50, 21000)]  # z = 0.5
    assert detect_unusual_data_volume(events) == []


def test_unusually_small_transfer_not_flagged():
    events = normal_history() + [transfer(50, 100)]
    assert detect_unusual_data_volume(events) == []


def test_not_enough_history_is_skipped():
    events = normal_history(count=3) + [transfer(50, 500000)]
    assert detect_unusual_data_volume(events) == []


def test_ignores_other_event_types_and_missing_bytes():
    events = normal_history()
    events.append(transfer(50, 500000, etype="LOGIN"))
    events.append(transfer(51, None))
    assert detect_unusual_data_volume(events) == []


def test_users_are_separate():
    events = normal_history("alice") + normal_history("bob")
    events.append(transfer(50, 500000, user="bob"))
    result = detect_unusual_data_volume(events)
    assert [d["username"] for d in result] == ["bob"]


def test_custom_threshold():
    events = normal_history() + [transfer(50, 24000)]  # z = 2.0
    assert detect_unusual_data_volume(events) == []
    assert len(detect_unusual_data_volume(events, z_threshold=2.0)) == 1


if __name__ == "__main__":
    test_large_transfer_is_flagged()
    test_normal_transfers_not_flagged()
    test_unusually_small_transfer_not_flagged()
    test_not_enough_history_is_skipped()
    test_ignores_other_event_types_and_missing_bytes()
    test_users_are_separate()
    test_custom_threshold()
    print("All data volume detector tests passed.")