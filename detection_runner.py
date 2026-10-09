from dotenv import load_dotenv

from db import get_db_connection
from rules import detect_brute_force
from incident_store import save_detections

load_dotenv()


def load_login_events():
    """Load LOGIN events from security_events as a list of dicts (None if DB unavailable)."""
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT event_id, timestamp, username, source_ip, event_type, status "
            "FROM security_events WHERE event_type = %s ORDER BY timestamp",
            ("LOGIN",)
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"Load error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def run_brute_force_detection(threshold=5, window_minutes=10):
    """Return a list of brute-force detections from stored events (None on DB failure)."""
    events = load_login_events()
    if events is None:
        return None
    return detect_brute_force(events, threshold=threshold, window_minutes=window_minutes)


if __name__ == "__main__":
    detections = run_brute_force_detection()
    if detections is None:
        raise SystemExit("Could not load events from the database.")

    print(f"Brute-force detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | ip={d['source_ip']} | users={d['usernames']} | "
              f"attempts={d['failed_attempts']} | {d['first_seen']} -> {d['last_seen']} | "
              f"severity={d['severity']}")
    saved = save_detections(detections)
    if saved is None:
        raise SystemExit("Could not save incidents.")
    print(f"Incidents created: {saved['created']} | skipped (already saved): {saved['skipped']}")