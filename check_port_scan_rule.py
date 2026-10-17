from dotenv import load_dotenv

from db import get_db_connection
from rules import detect_port_scan

load_dotenv()


def load_network_events():
    """Load NETWORK_CONNECTION events (None if DB unavailable)."""
    conn = get_db_connection()
    if not conn:
        return None
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT event_id, timestamp, source_ip, destination_ip, destination_port, "
            "event_type FROM security_events WHERE event_type = %s ORDER BY timestamp",
            ("NETWORK_CONNECTION",)
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
    events = load_network_events()
    if events is None:
        raise SystemExit("Could not load events from the database.")

    detections = detect_port_scan(events)
    print(f"Port scan detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | src={d['source_ip']} -> dst={d['destination_ip']} | "
              f"distinct_ports={d['distinct_ports']} | "
              f"{d['first_seen']} -> {d['last_seen']} | ports={d['ports']}")