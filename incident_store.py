
import json

from db import get_db_connection


def _risk_values(detection):
    risk = detection.get("risk")

    if not risk:
        return None, None, None

    return (
        risk["score"],
        risk["level"],
        json.dumps(risk["factors"]),
    )


def save_detections(detections):
    conn = get_db_connection()

    if not conn:
        return None

    cursor = None
    result = {"created": [], "skipped": 0}

    try:
        cursor = conn.cursor()

        for detection in detections:
            score, level, factors_json = _risk_values(detection)

            cursor.execute(
                """
                SELECT id
                FROM incidents
                WHERE rule = %s
                  AND source_ip <=> %s
                  AND first_seen = %s
                """,
                (
                    detection["rule"],
                    detection["source_ip"],
                    detection["first_seen"],
                ),
            )

            existing = cursor.fetchone()

            if existing:
                if score is not None:
                    cursor.execute(
                        """
                        UPDATE incidents
                        SET risk_score = %s,
                            risk_level = %s,
                            risk_factors = %s
                        WHERE id = %s
                        """,
                        (score, level, factors_json, existing[0]),
                    )

                result["skipped"] += 1
                continue

            usernames = detection.get("usernames") or []
            affected_user = usernames[0] if usernames else None

            summary = (
                f"{detection['failed_attempts']} failed logins from "
                f"{detection['source_ip']} against "
                f"{', '.join(usernames) or 'unknown user'}"
            )[:255]

            cursor.execute(
                """
                INSERT INTO incidents (
                    rule, classification, affected_user, source_ip,
                    severity, summary, first_seen, last_seen,
                    risk_score, risk_level, risk_factors
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    detection["rule"],
                    "BRUTE_FORCE",
                    affected_user,
                    detection["source_ip"],
                    detection["severity"],
                    summary,
                    detection["first_seen"],
                    detection["last_seen"],
                    score,
                    level,
                    factors_json,
                ),
            )

            incident_id = cursor.lastrowid
            incident_code = f"INC-{1000 + incident_id}"

            cursor.execute(
                "UPDATE incidents SET incident_code = %s WHERE id = %s",
                (incident_code, incident_id),
            )

            event_ids = detection.get("event_ids") or []

            if event_ids:
                cursor.executemany(
                    """
                    INSERT INTO incident_events (incident_id, event_id)
                    VALUES (%s, %s)
                    """,
                    [(incident_id, event_id) for event_id in event_ids],
                )

            result["created"].append(incident_code)

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