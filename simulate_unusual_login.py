import argparse
from datetime import datetime

from dotenv import load_dotenv

from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

SCENARIO = "unusual_login_hour"


def build_unusual_login_event(user="alice", ip="192.168.50.77"):
    """One simulated successful login at 02:30 from a fictional unfamiliar address."""
    return {
        "timestamp": datetime(2025, 1, 10, 2, 30, 0),
        "username": user,
        "source_ip": ip,
        "device_id": "UNKNOWN-DEVICE",
        "event_type": "LOGIN", "action": "LOGIN", "status": "SUCCESS",
        "severity": "MEDIUM",
        "metadata": {"scenario": SCENARIO, "simulated": True},
    }


def main():
    parser = argparse.ArgumentParser(description="Insert one simulated unusual-hour login.")
    parser.add_argument("--user", default="alice")
    parser.add_argument("--clear", action="store_true",
                        help="Delete previous unusual-login simulation rows first")
    args = parser.parse_args()

    if args.clear:
        conn = get_db_connection()
        if not conn:
            raise SystemExit("Could not connect to database.")
        cursor = conn.cursor()
        # Only removes rows created by this scenario, not the brute-force simulation.
        cursor.execute(
            "DELETE FROM security_events WHERE source_type = %s "
            "AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.scenario')) = %s",
            ("simulation", SCENARIO)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print("Cleared previous unusual-login simulation rows.")

    result = insert_raw_events([build_unusual_login_event(args.user[:50])],
                               source_type="simulation")
    print(f"Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for e in result["errors"]:
        print(" -", e)


if __name__ == "__main__":
    main()