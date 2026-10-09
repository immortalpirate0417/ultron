import argparse
import random
from datetime import datetime, timedelta

from dotenv import load_dotenv

from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

ATTACKER_IP = "192.168.50.99"   # fictional lab address
TARGET_IP = "192.168.1.5"       # fictional lab server


def build_brute_force_events(attempts=12, target_user="alice", seed=42, succeed=False,
                             start=None):
    """Return raw event dicts for one simulated brute-force burst plus one noise failure."""
    rng = random.Random(seed)
    ts = start or datetime(2025, 1, 8, 2, 15, 0)   # 02:15, outside working hours
    meta = {"scenario": "brute_force", "simulated": True}

    events = []
    for _ in range(attempts):
        ts += timedelta(seconds=rng.randint(5, 20))
        events.append({
            "timestamp": ts, "username": target_user,
            "source_ip": ATTACKER_IP, "destination_ip": TARGET_IP,
            "source_port": rng.randint(40000, 60000), "destination_port": 22,
            "device_id": "UNKNOWN-DEVICE",
            "event_type": "LOGIN", "action": "LOGIN", "status": "FAILURE",
            "severity": "MEDIUM", "metadata": meta,
        })

    if succeed:
        ts += timedelta(seconds=rng.randint(5, 20))
        events.append({
            "timestamp": ts, "username": target_user,
            "source_ip": ATTACKER_IP, "destination_ip": TARGET_IP,
            "source_port": rng.randint(40000, 60000), "destination_port": 22,
            "device_id": "UNKNOWN-DEVICE",
            "event_type": "LOGIN", "action": "LOGIN", "status": "SUCCESS",
            "severity": "HIGH", "metadata": meta,
        })

    # Harmless noise: a single typo by a normal user from their usual IP.
    events.append({
        "timestamp": datetime(2025, 1, 8, 9, 40, 0), "username": "carol",
        "source_ip": "192.168.1.12", "device_id": "DEVICE-03",
        "event_type": "LOGIN", "action": "LOGIN", "status": "FAILURE",
        "severity": "LOW",
        "metadata": {"scenario": "benign_typo", "simulated": True},
    })
    return events


def main():
    parser = argparse.ArgumentParser(description="Insert a simulated brute-force scenario.")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--user", default="alice")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--succeed", action="store_true",
                        help="Add a successful login after the failures")
    parser.add_argument("--clear", action="store_true",
                        help="Delete existing simulation events first")
    args = parser.parse_args()

    if not 1 <= args.attempts <= 500:
        raise SystemExit("Use --attempts 1-500.")

    if args.clear:
        conn = get_db_connection()
        if not conn:
            raise SystemExit("Could not connect to database.")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_events WHERE source_type = %s", ("simulation",))
        conn.commit()
        cursor.close()
        conn.close()
        print("Cleared existing simulation events.")

    events = build_brute_force_events(args.attempts, args.user[:50], args.seed, args.succeed)
    result = insert_raw_events(events, source_type="simulation")
    print(f"Generated: {len(events)}, Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for e in result["errors"]:
        print(" -", e)


if __name__ == "__main__":
    main()