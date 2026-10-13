from collections import defaultdict
from statistics import mean, pstdev

MIN_STD = 1.0  # floor (in hours) so very regular users don't make tiny deviations look huge


def _hour_of_day(ts):
    return ts.hour + ts.minute / 60.0


def detect_unusual_login_hour(events, z_threshold=3.0, min_history=5):
    """
    Flag successful logins whose time of day is unusual for that user.

    `events` is a list of dicts using the security_events field names
    (timestamp as datetime, username, event_type, status, and optionally
    event_id, source_ip). For each login, the baseline is the user's OTHER
    successful logins. Users with fewer than `min_history` other logins are skipped.
    Returns a list of detection dicts, ordered by time.
    """
    by_user = defaultdict(list)
    for e in events:
        if (e.get("event_type") == "LOGIN"
                and e.get("status") == "SUCCESS"
                and e.get("username")
                and e.get("timestamp") is not None):
            by_user[e["username"]].append(e)

    detections = []
    for user, logins in by_user.items():
        hours = [_hour_of_day(e["timestamp"]) for e in logins]
        for idx, e in enumerate(logins):
            others = hours[:idx] + hours[idx + 1:]
            if len(others) < min_history:
                continue
            base_mean = mean(others)
            base_std = max(pstdev(others), MIN_STD)
            z = (hours[idx] - base_mean) / base_std
            if abs(z) >= z_threshold:
                detections.append({
                    "rule": "UNUSUAL_LOGIN_HOUR",
                    "username": user,
                    "source_ip": e.get("source_ip"),
                    "timestamp": e["timestamp"],
                    "event_id": e.get("event_id"),
                    "login_hour": round(hours[idx], 2),
                    "baseline_mean_hour": round(base_mean, 2),
                    "baseline_std_hours": round(base_std, 2),
                    "z_score": round(z, 2),
                    "severity": "MEDIUM",
                })

    detections.sort(key=lambda d: d["timestamp"])
    return detections