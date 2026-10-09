from collections import defaultdict
from datetime import timedelta


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