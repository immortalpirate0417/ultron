from dotenv import load_dotenv

from db import get_db_connection
from anomaly_stats import detect_unusual_login_hour

load_dotenv()


def load_success_logins():
    """Load successful LOGIN events as a list of dicts (None if DB unavailable)."""
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT event_id, timestamp, username, source_ip, event_type, status "
            "FROM security_events WHERE event_type = %s AND status = %s "
            "ORDER BY timestamp",
            ("LOGIN", "SUCCESS")
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"Load error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def run_unusual_login_hour_detection(z_threshold=3.0, min_history=5):
    """Return unusual-login-hour detections from stored events (None on DB failure)."""
    events = load_success_logins()
    if events is None:
        return None
    return detect_unusual_login_hour(events, z_threshold=z_threshold,
                                     min_history=min_history)


if __name__ == "__main__":
    detections = run_unusual_login_hour_detection()
    if detections is None:
        raise SystemExit("Could not load events from the database.")

    print(f"Unusual login hour detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | user={d['username']} | ip={d['source_ip']} | "
              f"time={d['timestamp']} | hour={d['login_hour']} | "
              f"usual={d['baseline_mean_hour']} (std {d['baseline_std_hours']}) | "
              f"z={d['z_score']}")