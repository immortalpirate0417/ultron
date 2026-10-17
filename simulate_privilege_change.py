import argparse
from datetime import datetime

from dotenv import load_dotenv

from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

SCENARIO = "privilege_change"


def build_privilege_events(user="bob", ip="192.168.50.66"):
    """One simulated suspicious grant of ADMIN plus one benign ordinary-level change."""
    return [
        {
            "timestamp": datetime(2025, 1, 11, 3, 10, 0),
            "username": user,
            "source_ip": ip,
            "device_id": "UNKNOWN-DEVICE",
            "event_type": "PRIVILEGE_CHANGE", "action": "GRANT", "status": "SUCCESS",
            "resource": "role:admin",
            "privilege_level": "ADMIN",
            "severity": "HIGH",
            "metadata": {"scenario": SCENARIO, "simulated": True},
        },
        {
            # Harmless noise: routine change to an ordinary level during working hours.
            "timestamp": datetime(2025, 1, 10, 11, 0, 0),
            "username": "carol",
            "source_ip": "192.168.1.12",
            "device_id": "DEVICE-03",
            "event_type": "PRIVILEGE_CHANGE", "action": "GRANT", "status": "SUCCESS",
            "resource": "role:analyst",
            "privilege_level": "ANALYST",
            "severity": "INFO",
            "metadata": {"scenario": SCENARIO, "simulated": True, "benign": True},
        },
    ]


def main():
    parser = argparse.ArgumentParser(description="Insert a simulated privilege-change scenario.")
    parser.add_argument("--user", default="bob")
    parser.add_argument("--clear", action="store_true",
                        help="Delete previous privilege-change simulation rows first")
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
        print("Cleared previous privilege-change simulation rows.")

    result = insert_raw_events(build_privilege_events(args.user[:50]),
                               source_type="simulation")
    print(f"Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for e in result["errors"]:
        print(" -", e)


if __name__ == "__main__":
    main()