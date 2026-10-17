from datetime import datetime
from rules import detect_privilege_change

T = datetime(2025, 1, 11, 3, 10, 0)


def change(level="admin", user="bob", status="SUCCESS", etype="PRIVILEGE_CHANGE",
           event_id=None, ip="192.168.50.66", ts=T, resource="role:admin"):
    return {
        "timestamp": ts, "username": user, "source_ip": ip, "event_type": etype,
        "status": status, "privilege_level": level, "event_id": event_id,
        "resource": resource,
    }


def test_admin_grant_is_flagged():
    result = detect_privilege_change([change(event_id=7)])
    assert len(result) == 1
    d = result[0]
    assert d["rule"] == "PRIVILEGE_CHANGE"
    assert d["username"] == "bob"
    assert d["source_ip"] == "192.168.50.66"
    assert d["event_id"] == 7
    assert d["privilege_level"] == "ADMIN"
    assert d["resource"] == "role:admin"
    assert d["severity"] == "HIGH"


def test_matching_is_case_insensitive():
    events = [change("Root"), change(" superuser ")]
    assert len(detect_privilege_change(events)) == 2


def test_ordinary_level_not_flagged():
    assert detect_privilege_change([change("analyst"), change("user")]) == []


def test_failed_change_not_flagged():
    assert detect_privilege_change([change(status="FAILURE")]) == []


def test_other_event_types_ignored():
    assert detect_privilege_change([change(etype="LOGIN")]) == []


def test_missing_fields_ignored():
    assert detect_privilege_change([change(level=None), change(user=None)]) == []


def test_results_sorted_by_time():
    later = datetime(2025, 1, 11, 9, 0, 0)
    result = detect_privilege_change([change(user="late", ts=later), change(user="early")])
    assert [d["username"] for d in result] == ["early", "late"]


def test_custom_levels():
    assert len(detect_privilege_change([change("operator")],
                                       sensitive_levels=("operator",))) == 1


if __name__ == "__main__":
    test_admin_grant_is_flagged()
    test_matching_is_case_insensitive()
    test_ordinary_level_not_flagged()
    test_failed_change_not_flagged()
    test_other_event_types_ignored()
    test_missing_fields_ignored()
    test_results_sorted_by_time()
    test_custom_levels()
    print("All privilege rule tests passed.")