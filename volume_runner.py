from dotenv import load_dotenv

from db import get_db_connection
from anomaly_stats import detect_unusual_data_volume, VOLUME_EVENT_TYPES

load_dotenv()


def load_transfer_events():
    """Load FILE_ACCESS / DB_ACCESS events that have a byte count (None if DB unavailable)."""
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT event_id, timestamp, username, source_ip, event_type, resource, "
            "bytes_transferred FROM security_events "
            "WHERE event_type IN (%s, %s) AND bytes_transferred IS NOT NULL "
            "ORDER BY timestamp",
            VOLUME_EVENT_TYPES
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"Load error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def run_unusual_data_volume_detection(z_threshold=3.0, min_history=5):
    """Return unusual-data-volume detections from stored events (None on DB failure)."""
    events = load_transfer_events()
    if events is None:
        return None
    return detect_unusual_data_volume(events, z_threshold=z_threshold,
                                      min_history=min_history)


if __name__ == "__main__":
    detections = run_unusual_data_volume_detection()
    if detections is None:
        raise SystemExit("Could not load events from the database.")

    print(f"Unusual data volume detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | user={d['username']} | ip={d['source_ip']} | "
              f"time={d['timestamp']} | type={d['event_type']} | "
              f"resource={d['resource']} | bytes={d['bytes_transferred']} | "
              f"usual={d['baseline_mean_bytes']} (std {d['baseline_std_bytes']}) | "
              f"z={d['z_score']}")