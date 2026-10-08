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