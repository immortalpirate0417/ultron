import argparse
from datetime import datetime

from dotenv import load_dotenv

from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

SCENARIO = "unusual_data_volume"


def build_large_transfer_event(user="alice", ip="192.168.50.88", size=5_000_000):
    """One simulated oversized file read from a fictional unfamiliar address."""
    return {
        "timestamp": datetime(2025, 1, 9, 22, 40, 0),
        "username": user,
        "source_ip": ip,
        "device_id": "UNKNOWN-DEVICE",
        "event_type": "FILE_ACCESS", "action": "READ", "status": "SUCCESS",
        "resource": "/data/hr_records.csv",
        "bytes_transferred": size,
        "severity": "MEDIUM",
        "metadata": {"scenario": SCENARIO, "simulated": True},
    }


def main():
    parser = argparse.ArgumentParser(description="Insert one simulated large data transfer.")
    parser.add_argument("--user", default="alice")
    parser.add_argument("--size", type=int, default=5_000_000, help="Bytes transferred")
    parser.add_argument("--clear", action="store_true",
                        help="Delete previous data-volume simulation rows first")
    args = parser.parse_args()

    if not 1 <= args.size <= 10_000_000_000:
        raise SystemExit("Use --size between 1 and 10000000000.")

    if args.clear:
        conn = get_db_connection()
        if not conn:
            raise SystemExit("Could not connect to database.")
        cursor = conn.cursor()
        # Only removes rows created by this scenario.
        cursor.execute(
            "DELETE FROM security_events WHERE source_type = %s "
            "AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.scenario')) = %s",
            ("simulation", SCENARIO)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print("Cleared previous data-volume simulation rows.")

    result = insert_raw_events(
        [build_large_transfer_event(args.user[:50], size=args.size)],
        source_type="simulation"
    )
    print(f"Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for e in result["errors"]:
        print(" -", e)


if __name__ == "__main__":
    main()