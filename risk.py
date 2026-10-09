
def risk_level(score):
    """Map a 0-100 score to a level name."""
    if score <= 20:
        return "LOW"
    if score <= 40:
        return "MEDIUM"
    if score <= 70:
        return "HIGH"
    return "CRITICAL"


def score_brute_force(
    failed_attempts,
    first_seen,
    success_after=False,
    work_start=8,
    work_end=18
):
    """
    Score a brute-force detection.

    Returns:
        {
            "score": int,
            "level": str,
            "factors": [{"factor": str, "points": int}, ...]
        }
    """
    factors = []

    # Volume of failed attempts (maximum 40 points)
    if failed_attempts >= 50:
        points = 40
    elif failed_attempts >= 20:
        points = 30
    elif failed_attempts >= 10:
        points = 20
    else:
        points = 10

    factors.append({
        "factor": f"{failed_attempts} failed login attempts",
        "points": points
    })

    # Activity outside working hours (maximum 15 points)
    hour = first_seen.hour
    if hour < work_start or hour >= work_end:
        factors.append({
            "factor": f"Attempts started outside working hours ({hour:02d}:00)",
            "points": 15
        })

    # Successful login following failures (maximum 40 points)
    if success_after:
        factors.append({
            "factor": "Successful login from the same IP after failures",
            "points": 40
        })

    score = min(100, sum(f["points"] for f in factors))

    return {
        "score": score,
        "level": risk_level(score),
        "factors": factors
    }