def risk_level(score):
    """Map a 0-100 score to a level name."""
    if score <= 20:
        return "LOW"
    if score <= 40:
        return "MEDIUM"
    if score <= 70:
        return "HIGH"
    return "CRITICAL"


def score_brute_force(failed_attempts, first_seen, success_after=False,
                      work_start=8, work_end=18):
    """
    Score a brute-force detection.

    failed_attempts: number of failed logins in the burst
    first_seen: datetime of the first failure
    success_after: True if the same IP had a successful login right after the failures
    Returns {"score": int, "level": str, "factors": [{"factor": str, "points": int}, ...]}
    """
    factors = []

    # Volume of failed attempts (max 40)
    if failed_attempts >= 50:
        points = 40
    elif failed_attempts >= 20:
        points = 30
    elif failed_attempts >= 10:
        points = 20
    else:
        points = 10
    factors.append({"factor": f"{failed_attempts} failed login attempts", "points": points})

    # Activity outside working hours (max 15)
    hour = first_seen.hour
    if hour < work_start or hour >= work_end:
        factors.append({"factor": f"Attempts started outside working hours ({hour:02d}:00)",
                        "points": 15})

    # Successful login after failures suggests possible compromise (max 40)
    if success_after:
        factors.append({"factor": "Successful login from the same IP after failures",
                        "points": 40})

    score = min(100, sum(f["points"] for f in factors))
    return {"score": score, "level": risk_level(score), "factors": factors}


def score_unusual_login_hour(z_score, timestamp, new_source_ip=False,
                             work_start=8, work_end=18):
    """
    Score an unusual-login-hour detection.

    z_score: deviation from the user's usual login time (sign ignored)
    timestamp: datetime of the login
    new_source_ip: True if the user has not logged in from this IP before
    Returns {"score": int, "level": str, "factors": [{"factor": str, "points": int}, ...]}
    """
    factors = []
    deviation = abs(z_score)

    # How far from the user's normal time (max 30)
    if deviation >= 6:
        points = 30
    elif deviation >= 4:
        points = 25
    else:
        points = 20
    factors.append({"factor": f"Login time is {deviation:.1f} standard deviations from the user's usual",
                    "points": points})

    # Outside working hours (15)
    if timestamp.hour < work_start or timestamp.hour >= work_end:
        factors.append({"factor": f"Login outside working hours ({timestamp:%H:%M})",
                        "points": 15})

    # Unfamiliar source address (20)
    if new_source_ip:
        factors.append({"factor": "Login from an IP address not previously used by this user",
                        "points": 20})

    score = min(100, sum(f["points"] for f in factors))
    return {"score": score, "level": risk_level(score), "factors": factors}


def score_unusual_data_volume(z_score, bytes_transferred, baseline_mean_bytes, timestamp,
                              new_source_ip=False, work_start=8, work_end=18):
    """
    Score an unusual-data-volume detection.

    z_score: how many standard deviations above the user's usual transfer size
    bytes_transferred: size of the flagged transfer
    baseline_mean_bytes: the user's usual (mean) transfer size
    timestamp: datetime of the transfer
    new_source_ip: True if the user has not used this IP before
    Returns {"score": int, "level": str, "factors": [{"factor": str, "points": int}, ...]}
    """
    factors = []

    # How far above the user's normal (max 30)
    if z_score >= 10:
        points = 30
    elif z_score >= 5:
        points = 25
    else:
        points = 20
    factors.append({"factor": f"Transfer is {z_score:.1f} standard deviations above the user's usual",
                    "points": points})

    # How many times larger than the usual transfer (max 25)
    ratio = (bytes_transferred / baseline_mean_bytes) if baseline_mean_bytes > 0 else 0
    if ratio >= 100:
        points = 25
    elif ratio >= 20:
        points = 20
    elif ratio >= 5:
        points = 10
    else:
        points = 0
    if points:
        factors.append({"factor": f"Transfer is {ratio:.0f}x the user's average size",
                        "points": points})

    # Outside working hours (15)
    if timestamp.hour < work_start or timestamp.hour >= work_end:
        factors.append({"factor": f"Transfer outside working hours ({timestamp:%H:%M})",
                        "points": 15})

    # Unfamiliar source address (20)
    if new_source_ip:
        factors.append({"factor": "Transfer from an IP address not previously used by this user",
                        "points": 20})

    score = min(100, sum(f["points"] for f in factors))
    return {"score": score, "level": risk_level(score), "factors": factors}


def score_privilege_change(privilege_level, timestamp, new_source_ip=False,
                           work_start=8, work_end=18):
    """
    Score a privilege-change detection.

    privilege_level: the level that was granted (case-insensitive)
    timestamp: datetime of the change
    new_source_ip: True if the user has not used this IP before
    Returns {"score": int, "level": str, "factors": [{"factor": str, "points": int}, ...]}
    """
    factors = []
    level_name = (privilege_level or "").strip().upper()

    # Power of the granted level (max 40)
    if level_name in ("ROOT", "SUPERUSER"):
        points = 40
    elif level_name == "ADMIN":
        points = 35
    else:
        points = 20
    factors.append({"factor": f"Privilege granted: {level_name or 'UNKNOWN'}", "points": points})

    # Outside working hours (15)
    if timestamp.hour < work_start or timestamp.hour >= work_end:
        factors.append({"factor": f"Privilege change outside working hours ({timestamp:%H:%M})",
                        "points": 15})

    # Unfamiliar source address (20)
    if new_source_ip:
        factors.append({"factor": "Privilege change from an IP address not previously used by this user",
                        "points": 20})

    score = min(100, sum(f["points"] for f in factors))
    return {"score": score, "level": risk_level(score), "factors": factors}


def score_port_scan(distinct_ports, first_seen, open_ports_found=0,
                    work_start=8, work_end=18):
    """
    Score a port-scan detection.

    distinct_ports: number of different destination ports probed
    first_seen: datetime of the first probe
    open_ports_found: number of probed ports that accepted the connection
    Returns {"score": int, "level": str, "factors": [{"factor": str, "points": int}, ...]}
    """
    factors = []

    # Breadth of the scan (max 40)
    if distinct_ports >= 50:
        points = 40
    elif distinct_ports >= 20:
        points = 30
    else:
        points = 20
    factors.append({"factor": f"Scan probed {distinct_ports} distinct ports", "points": points})

    # Outside working hours (15)
    if first_seen.hour < work_start or first_seen.hour >= work_end:
        factors.append({"factor": f"Scan started outside working hours ({first_seen:%H:%M})",
                        "points": 15})

    # Open services discovered (20)
    if open_ports_found > 0:
        factors.append({"factor": f"{open_ports_found} probed port(s) accepted the connection (open services found)",
                        "points": 20})

    score = min(100, sum(f["points"] for f in factors))
    return {"score": score, "level": risk_level(score), "factors": factors}