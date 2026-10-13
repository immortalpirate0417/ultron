from datetime import datetime, timedelta
from anomaly_stats import detect_unusual_login_hour

DAY1 = datetime(2025, 1, 6)


def login(day, hour, minute=0, user="alice", status="SUCCESS", etype="LOGIN",
          event_id=None, ip="192.168.1.10"):
    return {
        "timestamp": (DAY1 + timedelta(days=day)).replace(hour=hour, minute=minute),
        "username": user, "source_ip": ip, "event_type": etype,
        "status": status, "event_id": event_id,
    }


def normal_history(user="alice", days=6):
    return [login(d, 9, user=user, event_id=d + 1) for d in range(days)]


def test_night_login_is_flagged():
    events = normal_history() + [login(10, 2, event_id=99, ip="192.168.50.99")]
    result = detect_unusual_login_hour(events)
    assert len(result) == 1
    d = result[0]
    assert d["rule"] == "UNUSUAL_LOGIN_HOUR"
    assert d["username"] == "alice"
    assert d["event_id"] == 99
    assert d["source_ip"] == "192.168.50.99"
    assert d["login_hour"] == 2.0
    assert d["baseline_mean_hour"] == 9.0
    assert d["baseline_std_hours"] == 1.0
    assert d["z_score"] == -7.0


def test_normal_logins_not_flagged():
    events = normal_history() + [login(10, 11)]  # 2 hours off: z = 2.0, below 3
    assert detect_unusual_login_hour(events) == []


def test_not_enough_history_is_skipped():
    events = [login(d, 9) for d in range(3)] + [login(10, 2)]
    assert detect_unusual_login_hour(events) == []


def test_failures_and_other_events_ignored():
    events = normal_history()
    events += [login(10, 2, status="FAILURE"), login(11, 2, etype="FILE_ACCESS")]
    assert detect_unusual_login_hour(events) == []


def test_users_are_separate():
    events = normal_history("alice") + normal_history("bob")
    events.append(login(10, 3, user="bob"))
    result = detect_unusual_login_hour(events)
    assert [d["username"] for d in result] == ["bob"]


def test_custom_threshold():
    events = normal_history() + [login(10, 11)]  # z = 2.0
    assert len(detect_unusual_login_hour(events, z_threshold=2.0)) == 1


if __name__ == "__main__":
    test_night_login_is_flagged()
    test_normal_logins_not_flagged()
    test_not_enough_history_is_skipped()
    test_failures_and_other_events_ignored()
    test_users_are_separate()
    test_custom_threshold()
    print("All statistical detector tests passed.")