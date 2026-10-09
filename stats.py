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
    Return total, high-severity, and critical-severity incident counts.
    Return None if the database is unavailable or the query fails.
    """
    conn = get_db_connection()
    if not conn:
        return None

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*), "
            "COALESCE(SUM(severity = %s), 0), "
            "COALESCE(SUM(severity = %s), 0) "
            "FROM incidents",
            ("HIGH", "CRITICAL")
        )
        total, high, critical = cursor.fetchone()
        return {
            "total": int(total),
            "high": int(high),
            "critical": int(critical)
        }
    except Exception as e:
        print(f"Stats error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()