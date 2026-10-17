from dotenv import load_dotenv

from db import get_db_connection
from rules import detect_privilege_change

load_dotenv()


def load_privilege_events():
    """Load PRIVILEGE_CHANGE events (None if DB unavailable)."""
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT event_id, timestamp, username, source_ip, event_type, status, "
            "resource, privilege_level FROM security_events "
            "WHERE event_type = %s ORDER BY timestamp",
            ("PRIVILEGE_CHANGE",)
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"Load error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


if __name__ == "__main__":
    events = load_privilege_events()
    if events is None:
        raise SystemExit("Could not load events from the database.")

    detections = detect_privilege_change(events)
    print(f"Privilege change detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | user={d['username']} | ip={d['source_ip']} | "
              f"time={d['timestamp']} | level={d['privilege_level']} | "
              f"resource={d['resource']}")