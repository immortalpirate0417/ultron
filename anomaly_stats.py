from collections import defaultdict
from statistics import mean, pstdev

MIN_STD = 1.0  # floor (in hours) so very regular users don't make tiny deviations look huge
VOLUME_EVENT_TYPES = ("FILE_ACCESS", "DB_ACCESS")
VOLUME_MIN_STD_RATIO = 0.10  # std floor for data volume = 10% of the baseline mean


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


def detect_unusual_data_volume(events, z_threshold=3.0, min_history=5):
    """
    Flag FILE_ACCESS / DB_ACCESS events whose bytes_transferred is unusually
    HIGH for that user (z-score >= z_threshold). Unusually small transfers are ignored.

    For each event, the baseline is the user's OTHER transfers. Users with fewer
    than `min_history` other transfers are skipped. The baseline std is at least
    10% of the baseline mean (and at least 1 byte).
    Returns a list of detection dicts, ordered by time.
    """
    by_user = defaultdict(list)
    for e in events:
        if (e.get("event_type") in VOLUME_EVENT_TYPES
                and e.get("bytes_transferred") is not None
                and e.get("username")
                and e.get("timestamp") is not None):
            by_user[e["username"]].append(e)

    detections = []
    for user, items in by_user.items():
        volumes = [float(e["bytes_transferred"]) for e in items]
        for idx, e in enumerate(items):
            others = volumes[:idx] + volumes[idx + 1:]
            if len(others) < min_history:
                continue
            base_mean = mean(others)
            base_std = max(pstdev(others), base_mean * VOLUME_MIN_STD_RATIO, 1.0)
            z = (volumes[idx] - base_mean) / base_std
            if z >= z_threshold:
                detections.append({
                    "rule": "UNUSUAL_DATA_VOLUME",
                    "username": user,
                    "source_ip": e.get("source_ip"),
                    "timestamp": e["timestamp"],
                    "event_id": e.get("event_id"),
                    "event_type": e["event_type"],
                    "resource": e.get("resource"),
                    "bytes_transferred": int(volumes[idx]),
                    "baseline_mean_bytes": round(base_mean, 2),
                    "baseline_std_bytes": round(base_std, 2),
                    "z_score": round(z, 2),
                    "severity": "MEDIUM",
                })

    detections.sort(key=lambda d: d["timestamp"])
    return detections