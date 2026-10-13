import json

from db import get_db_connection


def _risk_values(d):
    """Return (score, level, factors_json) from a detection's optional 'risk' dict."""
    risk = d.get("risk")
    if not risk:
        return None, None, None
    return risk["score"], risk["level"], json.dumps(risk["factors"])


def _incident_fields(d):
    """
    Build the rule-specific incident fields from a detection dict.
    Returns (classification, affected_user, source_ip, summary, first_seen, last_seen, event_ids).
    """
    rule = d["rule"]

    if rule == "BRUTE_FORCE":
        users = d.get("usernames") or []
        summary = (f"{d['failed_attempts']} failed logins from {d['source_ip']} "
                   f"against {', '.join(users) or 'unknown user'}")
        return ("BRUTE_FORCE", users[0] if users else None, d["source_ip"],
                summary[:255], d["first_seen"], d["last_seen"], d.get("event_ids") or [])

    if rule == "UNUSUAL_LOGIN_HOUR":
        summary = (f"Login by {d['username']} at {d['timestamp']:%H:%M} from "
                   f"{d['source_ip'] or 'unknown IP'} is {abs(d['z_score']):.1f} standard "
                   f"deviations from the usual time ({d['baseline_mean_hour']:.1f}h)")
        event_ids = [d["event_id"]] if d.get("event_id") is not None else []
        return ("UNUSUAL_LOGIN", d["username"], d["source_ip"],
                summary[:255], d["timestamp"], d["timestamp"], event_ids)

    raise ValueError(f"Unsupported rule: {rule}")


def save_detections(detections):
    """
    Save detection dicts as incidents (with evidence links and risk score).
    If an incident with the same rule, source_ip, affected user and first_seen
    already exists, no new incident is created; its risk fields are refreshed instead.
    Returns {"created": [codes], "skipped": int}, or None on failure.
    """
    conn = get_db_connection()
    if not conn:
        return None

    cursor = None
    result = {"created": [], "skipped": 0}
    try:
        cursor = conn.cursor()
        for d in detections:
            score, level, factors_json = _risk_values(d)
            (classification, affected_user, source_ip, summary,
             first_seen, last_seen, event_ids) = _incident_fields(d)

            cursor.execute(
                "SELECT id FROM incidents WHERE rule = %s AND source_ip <=> %s "
                "AND affected_user <=> %s AND first_seen = %s",
                (d["rule"], source_ip, affected_user, first_seen)
            )
            existing = cursor.fetchone()
            if existing:
                if score is not None:
                    cursor.execute(
                        "UPDATE incidents SET risk_score = %s, risk_level = %s, risk_factors = %s "
                        "WHERE id = %s",
                        (score, level, factors_json, existing[0])
                    )
                result["skipped"] += 1
                continue

            cursor.execute(
                "INSERT INTO incidents (rule, classification, affected_user, source_ip, "
                "severity, summary, first_seen, last_seen, risk_score, risk_level, risk_factors) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (d["rule"], classification, affected_user, source_ip,
                 d["severity"], summary, first_seen, last_seen,
                 score, level, factors_json)
            )
            incident_id = cursor.lastrowid
            code = f"INC-{1000 + incident_id}"
            cursor.execute("UPDATE incidents SET incident_code = %s WHERE id = %s",
                           (code, incident_id))

            if event_ids:
                cursor.executemany(
                    "INSERT INTO incident_events (incident_id, event_id) VALUES (%s, %s)",
                    [(incident_id, eid) for eid in event_ids]
                )
            result["created"].append(code)

        conn.commit()
        return result
    except Exception as e:
        conn.rollback()
        print(f"Incident save error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()

VALID_STATUSES = ("OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")


def update_incident_status(incident_id, new_status):
    """
    Set an incident's status. Returns (old_status, new_status) on success,
    or None if the incident does not exist, the status is invalid, or the DB fails.
    """
    if new_status not in VALID_STATUSES:
        return None

    conn = get_db_connection()
    if not conn:
        return None

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None
        old_status = row[0]
        cursor.execute("UPDATE incidents SET status = %s WHERE id = %s",
                       (new_status, incident_id))
        conn.commit()
        return old_status, new_status
    except Exception as e:
        conn.rollback()
        print(f"Status update error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()