
from db import get_db_connection


def get_total_events():
    """Return the number of rows in security_events, or None if the database is unavailable."""
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_events")
        return cursor.fetchone()[0]
    except Exception as e:
        print(f"Stats error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def get_incident_counts():
    """
    Return {"total": int, "high": int, "critical": int} from the incidents table,
    using risk_level for high/critical. Returns None if the database is unavailable.
    """
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*), "
            "COALESCE(SUM(risk_level = %s), 0), "
            "COALESCE(SUM(risk_level = %s), 0) "
            "FROM incidents",
            ("HIGH", "CRITICAL")
        )
        total, high, critical = cursor.fetchone()
        return {"total": int(total), "high": int(high), "critical": int(critical)}
    except Exception as e:
        print(f"Stats error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def get_top_incidents(limit=5):
    """
    Return up to `limit` incidents ordered by risk score (highest first, unscored last).
    Returns an empty list if there are none or the database fails.
    """
    conn = get_db_connection()
    if not conn:
        return []
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, incident_code, classification, affected_user, source_ip, "
            "status, risk_score, risk_level, first_seen "
            "FROM incidents "
            "ORDER BY (risk_score IS NULL), risk_score DESC, first_seen DESC, id DESC "
            "LIMIT %s",
            (int(limit),)
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"Stats error: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        conn.close()