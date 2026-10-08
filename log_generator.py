import argparse
import random
from datetime import datetime, timedelta

from dotenv import load_dotenv

from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

FIRST_NAMES = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    "ivan", "judy", "kevan", "laura", "mallory", "nina", "oscar", "peggy",
]
RESOURCES = [
    "/data/reports.xlsx", "/data/finance.csv", "/data/hr_records.csv",
    "/data/projects.docx", "/data/inventory.xlsx", "/data/notes.txt",
]
DB_TABLES = ["customers", "orders", "inventory", "invoices"]


def build_profiles(num_users, rng):
    """Create a stable behavior profile per simulated user."""
    names = FIRST_NAMES[:num_users]
    for i in range(len(names), num_users):
        names.append(f"user{i + 1:02d}")

    profiles = []
    for idx, name in enumerate(names):
        start_hour = rng.choice([8, 9, 10])
        profiles.append({
            "username": name,
            "ip": f"192.168.1.{10 + idx}",
            "device_id": f"DEVICE-{idx + 1:02d}",
            "start_hour": start_hour,
            "end_hour": start_hour + rng.choice([8, 9]),
            "resources": rng.sample(RESOURCES, 3),
            "avg_bytes": rng.choice([5000, 20000, 50000]),
        })
    return profiles


def generate_normal_events(num_users=5, days=7, seed=42, start_date=None):
    """Return a list of raw event dicts for normal working-hours activity."""
    rng = random.Random(seed)
    profiles = build_profiles(num_users, rng)
    if start_date is None:
        start_date = datetime(2025, 1, 6)  # fixed default keeps output reproducible

    events = []
    for day in range(days):
        date = start_date + timedelta(days=day)
        if date.weekday() >= 5:  # skip Saturday/Sunday
            continue
        for p in profiles:
            login_time = date.replace(
                hour=p["start_hour"], minute=rng.randint(0, 45), second=rng.randint(0, 59)
            )
            events.append({
                "timestamp": login_time, "username": p["username"],
                "source_ip": p["ip"], "device_id": p["device_id"],
                "event_type": "LOGIN", "action": "LOGIN", "status": "SUCCESS",
                "severity": "INFO", "metadata": {"simulated": True},
            })

            for _ in range(rng.randint(3, 8)):
                span = max(1, (p["end_hour"] - p["start_hour"] - 1) * 60)
                ts = login_time + timedelta(minutes=rng.randint(5, span),
                                            seconds=rng.randint(0, 59))
                if rng.random() < 0.7:
                    events.append({
                        "timestamp": ts, "username": p["username"],
                        "source_ip": p["ip"], "device_id": p["device_id"],
                        "event_type": "FILE_ACCESS", "action": "READ", "status": "SUCCESS",
                        "resource": rng.choice(p["resources"]),
                        "bytes_transferred": max(100, int(rng.gauss(p["avg_bytes"], p["avg_bytes"] * 0.2))),
                        "severity": "INFO", "metadata": {"simulated": True},
                    })
                else:
                    events.append({
                        "timestamp": ts, "username": p["username"],
                        "source_ip": p["ip"], "device_id": p["device_id"],
                        "event_type": "DB_ACCESS", "action": "SELECT", "status": "SUCCESS",
                        "resource": rng.choice(DB_TABLES),
                        "bytes_transferred": max(100, int(rng.gauss(p["avg_bytes"], p["avg_bytes"] * 0.2))),
                        "severity": "INFO", "metadata": {"simulated": True},
                    })

            logout_time = date.replace(hour=p["end_hour"], minute=rng.randint(0, 30), second=0)
            events.append({
                "timestamp": logout_time, "username": p["username"],
                "source_ip": p["ip"], "device_id": p["device_id"],
                "event_type": "LOGOUT", "action": "LOGOUT", "status": "SUCCESS",
                "severity": "INFO", "metadata": {"simulated": True},
            })

    events.sort(key=lambda e: e["timestamp"])
    return events


def main():
    parser = argparse.ArgumentParser(description="Generate simulated normal events.")
    parser.add_argument("--users", type=int, default=5)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--clear", action="store_true",
                        help="Delete existing synthetic events first")
    args = parser.parse_args()

    if not 1 <= args.users <= 50 or not 1 <= args.days <= 60:
        raise SystemExit("Use --users 1-50 and --days 1-60.")

    if args.clear:
        conn = get_db_connection()
        if not conn:
            raise SystemExit("Could not connect to database.")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_events WHERE source_type = %s", ("synthetic",))
        conn.commit()
        cursor.close()
        conn.close()
        print("Cleared existing synthetic events.")

    events = generate_normal_events(args.users, args.days, args.seed)
    result = insert_raw_events(events, source_type="synthetic")
    print(f"Generated: {len(events)}, Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for e in result["errors"]:
        print(" -", e)


if __name__ == "__main__":
    main()