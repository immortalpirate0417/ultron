import argparse
import random
from datetime import datetime, timedelta

from dotenv import load_dotenv

from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

SCENARIO = "port_scan"
SCANNER_IP = "192.168.50.55"   # fictional lab address
TARGET_IP = "192.168.1.5"      # fictional lab server
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
OPEN_PORTS = {22, 80, 443}


def build_port_scan_events(seed=42, start=None):
    """Return raw event dicts: one simulated scan burst plus benign repeated-port noise."""
    rng = random.Random(seed)
    ts = start or datetime(2025, 1, 12, 23, 50, 0)
    meta = {"scenario": SCENARIO, "simulated": True}

    events = []
    for port in SCAN_PORTS:
        events.append({
            "timestamp": ts, "source_ip": SCANNER_IP, "destination_ip": TARGET_IP,
            "source_port": rng.randint(40000, 60000), "destination_port": port,
            "event_type": "NETWORK_CONNECTION", "action": "CONNECT",
            "status": "SUCCESS" if port in OPEN_PORTS else "FAILURE",
            "severity": "LOW", "metadata": meta,
        })
        ts += timedelta(seconds=rng.randint(1, 5))

    # Harmless noise: a normal client reconnecting to the same HTTPS port.
    noise_start = datetime(2025, 1, 12, 10, 0, 0)
    for i in range(12):
        events.append({
            "timestamp": noise_start + timedelta(seconds=10 * i),
            "source_ip": "192.168.1.12", "destination_ip": TARGET_IP,
            "source_port": rng.randint(40000, 60000), "destination_port": 443,
            "event_type": "NETWORK_CONNECTION", "action": "CONNECT", "status": "SUCCESS",
            "severity": "INFO",
            "metadata": {"scenario": SCENARIO, "simulated": True, "benign": True},
        })
    return events


def main():
    parser = argparse.ArgumentParser(description="Insert a simulated port-scan scenario.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--clear", action="store_true",
                        help="Delete previous port-scan simulation rows first")
    args = parser.parse_args()

    if args.clear:
        conn = get_db_connection()
        if not conn:
            raise SystemExit("Could not connect to database.")
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM security_events WHERE source_type = %s "
            "AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.scenario')) = %s",
            ("simulation", SCENARIO)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print("Cleared previous port-scan simulation rows.")

    events = build_port_scan_events(args.seed)
    result = insert_raw_events(events, source_type="simulation")
    print(f"Generated: {len(events)}, Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for e in result["errors"]:
        print(" -", e)


if __name__ == "__main__":
    main()