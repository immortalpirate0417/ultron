from datetime import datetime
from risk import score_privilege_change

NIGHT = datetime(2025, 1, 11, 3, 10)
DAY = datetime(2025, 1, 11, 11, 0)


def test_admin_at_night():
    # 35 + 15 = 50
    r = score_privilege_change("ADMIN", NIGHT)
    assert r["score"] == 50
    assert r["level"] == "HIGH"
    assert len(r["factors"]) == 2


def test_admin_night_new_ip():
    # 35 + 15 + 20 = 70
    r = score_privilege_change("ADMIN", NIGHT, new_source_ip=True)
    assert r["score"] == 70
    assert r["level"] == "HIGH"
    assert len(r["factors"]) == 3


def test_root_night_new_ip_is_critical():
    # 40 + 15 + 20 = 75
    r = score_privilege_change("root", NIGHT, new_source_ip=True)
    assert r["score"] == 75
    assert r["level"] == "CRITICAL"


def test_daytime_levels():
    assert score_privilege_change("ADMIN", DAY)["score"] == 35
    assert score_privilege_change("SUPERUSER", DAY)["score"] == 40
    assert score_privilege_change("OPERATOR", DAY)["score"] == 20


def test_case_and_whitespace_are_ignored():
    assert score_privilege_change(" admin ", DAY)["score"] == 35


def test_missing_level_does_not_crash():
    r = score_privilege_change(None, DAY)
    assert r["score"] == 20
    assert r["factors"][0]["factor"] == "Privilege granted: UNKNOWN"


def test_working_hours_boundary():
    early = score_privilege_change("ADMIN", datetime(2025, 1, 11, 7, 59))
    start = score_privilege_change("ADMIN", datetime(2025, 1, 11, 8, 0))
    assert early["score"] == 50
    assert start["score"] == 35


def test_factors_sum_to_score():
    r = score_privilege_change("ROOT", NIGHT, new_source_ip=True)
    assert sum(f["points"] for f in r["factors"]) == r["score"]
    assert 0 <= r["score"] <= 100


if __name__ == "__main__":
    test_admin_at_night()
    test_admin_night_new_ip()
    test_root_night_new_ip_is_critical()
    test_daytime_levels()
    test_case_and_whitespace_are_ignored()
    test_missing_level_does_not_crash()
    test_working_hours_boundary()
    test_factors_sum_to_score()
    print("All privilege risk tests passed.")