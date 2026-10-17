from datetime import datetime
from risk import score_unusual_data_volume

NIGHT = datetime(2025, 1, 9, 22, 40)
DAY = datetime(2025, 1, 9, 11, 0)


def test_large_night_transfer():
    # z=240 -> 30; ratio 250x -> 25; night -> 15  = 70
    r = score_unusual_data_volume(240.0, 5_000_000, 20_000, NIGHT)
    assert r["score"] == 70
    assert r["level"] == "HIGH"
    assert len(r["factors"]) == 3


def test_new_ip_escalates_to_critical():
    # 30 + 25 + 15 + 20 = 90
    r = score_unusual_data_volume(240.0, 5_000_000, 20_000, NIGHT, new_source_ip=True)
    assert r["score"] == 90
    assert r["level"] == "CRITICAL"


def test_z_score_tiers():
    # ratio 1x so only the z-score factor applies, daytime
    assert score_unusual_data_volume(3.5, 20_000, 20_000, DAY)["score"] == 20
    assert score_unusual_data_volume(5.0, 20_000, 20_000, DAY)["score"] == 25
    assert score_unusual_data_volume(10.0, 20_000, 20_000, DAY)["score"] == 30


def test_ratio_tiers():
    # z tier fixed at 20 (z=3.5), daytime
    assert score_unusual_data_volume(3.5, 100_000, 20_000, DAY)["score"] == 30    # 5x   -> +10
    assert score_unusual_data_volume(3.5, 400_000, 20_000, DAY)["score"] == 40    # 20x  -> +20
    assert score_unusual_data_volume(3.5, 2_000_000, 20_000, DAY)["score"] == 45  # 100x -> +25
    assert score_unusual_data_volume(3.5, 80_000, 20_000, DAY)["score"] == 20     # 4x   -> +0


def test_zero_baseline_does_not_crash():
    r = score_unusual_data_volume(4.0, 1000, 0, DAY)
    assert r["score"] == 20
    assert len(r["factors"]) == 1


def test_factors_sum_to_score_and_cap():
    r = score_unusual_data_volume(500.0, 9_000_000, 10_000, NIGHT, new_source_ip=True)
    assert r["score"] == 90
    assert sum(f["points"] for f in r["factors"]) == r["score"]
    assert 0 <= r["score"] <= 100


if __name__ == "__main__":
    test_large_night_transfer()
    test_new_ip_escalates_to_critical()
    test_z_score_tiers()
    test_ratio_tiers()
    test_zero_baseline_does_not_crash()
    test_factors_sum_to_score_and_cap()
    print("All data volume risk tests passed.")