from dotenv import load_dotenv

from db import get_db_connection
from anomaly_stats import detect_unusual_data_volume, VOLUME_EVENT_TYPES
from risk import score_unusual_data_volume
from incident_store import save_detections

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


def load_first_ip_use():
    """
    Return {(username, source_ip): earliest timestamp} across ALL stored events
    (None if DB unavailable). Used to tell whether an IP is new for a user.
    """
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, source_ip, MIN(timestamp) FROM security_events "
            "WHERE username IS NOT NULL AND source_ip IS NOT NULL "
            "GROUP BY username, source_ip"
        )
        return {(u, ip): ts for u, ip, ts in cursor.fetchall()}
    except Exception as e:
        print(f"Load error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def is_new_source_ip(detection, first_ip_use):
    """True if the user had no earlier event from this detection's IP."""
    ip = detection["source_ip"]
    if not ip:
        return False
    first = first_ip_use.get((detection["username"], ip))
    return first is None or first >= detection["timestamp"]


def run_unusual_data_volume_detection(z_threshold=3.0, min_history=5):
    """Return unusual-data-volume detections, each with a 'risk' dict (None on DB failure)."""
    events = load_transfer_events()
    first_ip_use = load_first_ip_use()
    if events is None or first_ip_use is None:
        return None
    detections = detect_unusual_data_volume(events, z_threshold=z_threshold,
                                            min_history=min_history)
    for d in detections:
        d["new_source_ip"] = is_new_source_ip(d, first_ip_use)
        d["risk"] = score_unusual_data_volume(
            d["z_score"], d["bytes_transferred"], d["baseline_mean_bytes"],
            d["timestamp"], new_source_ip=d["new_source_ip"]
        )
    return detections


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
              f"z={d['z_score']} | new_ip={d['new_source_ip']} | "
              f"risk={d['risk']['score']} ({d['risk']['level']})")
        for f in d["risk"]["factors"]:
            print(f"    +{f['points']}  {f['factor']}")

    saved = save_detections(detections)
    if saved is None:
        raise SystemExit("Could not save incidents.")
    print(f"Incidents created: {saved['created']} | skipped (already saved, risk refreshed): {saved['skipped']}")