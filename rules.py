from collections import defaultdict
from datetime import timedelta

SENSITIVE_PRIVILEGE_LEVELS = ("ADMIN", "ROOT", "SUPERUSER")


def detect_brute_force(events, threshold=5, window_minutes=10):
    """
    Flag source IPs with >= `threshold` failed logins within `window_minutes`.

    `events` is a list of dicts using the security_events field names
    (timestamp as datetime, source_ip, username, event_type, status, and
    optionally event_id). Returns a list of detection dicts.

    Windows are non-overlapping per IP: after a detection, scanning resumes
    after that window, so one burst produces one detection.
    """
    window = timedelta(minutes=window_minutes)

    by_ip = defaultdict(list)
    for e in events:
        if (e.get("event_type") == "LOGIN"
                and e.get("status") == "FAILURE"
                and e.get("source_ip")
                and e.get("timestamp") is not None):
            by_ip[e["source_ip"]].append(e)

    detections = []
    for ip, failures in by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])
        n = len(failures)
        i = 0
        while i < n:
            j = i
            while j + 1 < n and failures[j + 1]["timestamp"] - failures[i]["timestamp"] <= window:
                j += 1
            count = j - i + 1
            if count >= threshold:
                group = failures[i:j + 1]
                detections.append({
                    "rule": "BRUTE_FORCE",
                    "source_ip": ip,
                    "usernames": sorted({e["username"] for e in group if e.get("username")}),
                    "failed_attempts": count,
                    "first_seen": group[0]["timestamp"],
                    "last_seen": group[-1]["timestamp"],
                    "event_ids": [e["event_id"] for e in group if e.get("event_id") is not None],
                    "severity": "HIGH",
                })
                i = j + 1
            else:
                i += 1
    return detections


def detect_privilege_change(events, sensitive_levels=SENSITIVE_PRIVILEGE_LEVELS):
    """
    Flag successful PRIVILEGE_CHANGE events that grant a sensitive privilege level.

    `events` is a list of dicts using the security_events field names
    (timestamp, username, source_ip, event_type, status, privilege_level,
    and optionally event_id, resource). Matching is case-insensitive.
    Returns a list of detection dicts, ordered by time.
    """
    levels = {lvl.upper() for lvl in sensitive_levels}
    detections = []
    for e in events:
        level = (e.get("privilege_level") or "").strip().upper()
        if (e.get("event_type") == "PRIVILEGE_CHANGE"
                and e.get("status") == "SUCCESS"
                and level in levels
                and e.get("username")
                and e.get("timestamp") is not None):
            detections.append({
                "rule": "PRIVILEGE_CHANGE",
                "username": e["username"],
                "source_ip": e.get("source_ip"),
                "timestamp": e["timestamp"],
                "event_id": e.get("event_id"),
                "privilege_level": level,
                "resource": e.get("resource"),
                "severity": "HIGH",
            })
    detections.sort(key=lambda d: d["timestamp"])
    return detections