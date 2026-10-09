
from datetime import datetime
from risk import risk_level, score_brute_force

NIGHT = datetime(2025, 1, 8, 2, 15, 0)
DAY = datetime(2025, 1, 8, 10, 0, 0)


def test_levels_at_boundaries():
    assert risk_level(0) == "LOW"
    assert risk_level(20) == "LOW"
    assert risk_level(21) == "MEDIUM"
    assert risk_level(40) == "MEDIUM"
    assert risk_level(41) == "HIGH"
    assert risk_level(70) == "HIGH"
    assert risk_level(71) == "CRITICAL"
    assert risk_level(100) == "CRITICAL"


def test_simulated_burst():
    # 12 attempts at night: 20 + 15 = 35
    result = score_brute_force(12, NIGHT)
    assert result["score"] == 35
    assert result["level"] == "MEDIUM"
    assert len(result["factors"]) == 2


def test_daytime_small_burst_is_low_or_medium():
    result = score_brute_force(5, DAY)
    assert result["score"] == 10
    assert result["level"] == "LOW"
    assert len(result["factors"]) == 1


def test_success_after_failures_escalates():
    # 12 attempts, night, success: 20 + 15 + 40 = 75
    result = score_brute_force(12, NIGHT, success_after=True)
    assert result["score"] == 75
    assert result["level"] == "CRITICAL"


def test_score_is_capped_at_100():
    result = score_brute_force(500, NIGHT, success_after=True)
    assert result["score"] == 95
    assert 0 <= result["score"] <= 100


def test_factor_points_sum_to_score():
    result = score_brute_force(25, NIGHT, success_after=True)
    assert sum(f["points"] for f in result["factors"]) == result["score"]


if __name__ == "__main__":
    test_levels_at_boundaries()
    test_simulated_burst()
    test_daytime_small_burst_is_low_or_medium()
    test_success_after_failures_escalates()
    test_score_is_capped_at_100()
    test_factor_points_sum_to_score()
    print("All risk tests passed.")