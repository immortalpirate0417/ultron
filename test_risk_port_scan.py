from datetime import datetime
from risk import score_port_scan

NIGHT = datetime(2025, 1, 12, 23, 50)
DAY = datetime(2025, 1, 12, 11, 0)


def test_simulated_scan():
    # 15 ports -> 20; 23:50 -> 15; open ports -> 20 = 55
    r = score_port_scan(15, NIGHT, open_ports_found=3)
    assert r["score"] == 55
    assert r["level"] == "HIGH"
    assert len(r["factors"]) == 3


def test_scan_without_open_ports():
    r = score_port_scan(15, NIGHT)
    assert r["score"] == 35
    assert r["level"] == "MEDIUM"
    assert len(r["factors"]) == 2


def test_breadth_tiers():
    assert score_port_scan(10, DAY)["score"] == 20
    assert score_port_scan(19, DAY)["score"] == 20
    assert score_port_scan(20, DAY)["score"] == 30
    assert score_port_scan(49, DAY)["score"] == 30
    assert score_port_scan(50, DAY)["score"] == 40


def test_working_hours_boundary():
    assert score_port_scan(10, datetime(2025, 1, 12, 7, 59))["score"] == 35
    assert score_port_scan(10, datetime(2025, 1, 12, 8, 0))["score"] == 20


def test_broad_night_scan_with_open_ports_is_critical():
    # 40 + 15 + 20 = 75
    r = score_port_scan(100, NIGHT, open_ports_found=5)
    assert r["score"] == 75
    assert r["level"] == "CRITICAL"


def test_factors_sum_to_score():
    r = score_port_scan(25, NIGHT, open_ports_found=2)
    assert sum(f["points"] for f in r["factors"]) == r["score"]
    assert 0 <= r["score"] <= 100


if __name__ == "__main__":
    test_simulated_scan()
    test_scan_without_open_ports()
    test_breadth_tiers()
    test_working_hours_boundary()
    test_broad_night_scan_with_open_ports_is_critical()
    test_factors_sum_to_score()
    print("All port scan risk tests passed.")