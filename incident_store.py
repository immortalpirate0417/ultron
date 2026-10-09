from db import get_db_connection


def save_detections(detections):
    """
    Save detection dicts as incidents (with evidence links).
    Skips a detection if an incident with the same rule, source_ip and
    first_seen already exists. Returns {"created": [codes], "skipped": int},
    or None if the database is unavailable.
    """
    conn = get_db_connection()
    if not conn:
        return None

    cursor = None
    result = {"created": [], "skipped": 0}
    try:
        cursor = conn.cursor()
        for d in detections:
            cursor.execute(
                "SELECT id FROM incidents WHERE rule = %s AND source_ip <=> %s AND first_seen = %s",
                (d["rule"], d["source_ip"], d["first_seen"])
            )
            if cursor.fetchone():
                result["skipped"] += 1
                continue

            users = d.get("usernames") or []
            affected_user = users[0] if users else None
            summary = (f"{d['failed_attempts']} failed logins from {d['source_ip']} "
                       f"against {', '.join(users) or 'unknown user'}")[:255]

            cursor.execute(
                "INSERT INTO incidents (rule, classification, affected_user, source_ip, "
                "severity, summary, first_seen, last_seen) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (d["rule"], "BRUTE_FORCE", affected_user, d["source_ip"],
                 d["severity"], summary, d["first_seen"], d["last_seen"])
            )
            incident_id = cursor.lastrowid
            code = f"INC-{1000 + incident_id}"
            cursor.execute("UPDATE incidents SET incident_code = %s WHERE id = %s",
                           (code, incident_id))

            if d.get("event_ids"):
                cursor.executemany(
                    "INSERT INTO incident_events (incident_id, event_id) VALUES (%s, %s)",
                    [(incident_id, eid) for eid in d["event_ids"]]
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