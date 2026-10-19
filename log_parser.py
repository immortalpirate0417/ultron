import argparse
import re
from datetime import datetime

from dotenv import load_dotenv

from event_store import insert_raw_events

load_dotenv()

# Example: "Jan 15 02:31:07 myhost sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 51234 ssh2"
LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+\w+\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_line(line, year):
    """Return a raw event dict for one auth.log line, or None if it is not a supported SSH login line."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    success = m["result"] == "Accepted"
    return {
        "timestamp": ts,
        "username": m["user"],
        "source_ip": m["ip"],
        "source_port": m["port"],
        "destination_port": 22,
        "device_id": m["host"],
        "event_type": "LOGIN", "action": "LOGIN",
        "status": "SUCCESS" if success else "FAILURE",
        "severity": "INFO" if success else "LOW",
        "raw_log": line.strip(),
        "metadata": {"source": "auth.log", "lab": True},
    }


def parse_file(path, year):
    """Return (events, skipped_count) for an auth.log file."""
    events, skipped = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            event = parse_line(line, year)
            if event:
                events.append(event)
            else:
                skipped += 1
    return events, skipped


def main():
    parser = argparse.ArgumentParser(description="Parse a Linux auth.log into ULTRON events.")
    parser.add_argument("path", help="Path to a copy of auth.log from your own VM")
    parser.add_argument("--year", type=int, default=datetime.now().year)
    parser.add_argument("--dry-run", action="store_true", help="Parse and report without inserting")
    args = parser.parse_args()

    events, skipped = parse_file(args.path, args.year)
    print(f"Parsed: {len(events)}, skipped (unsupported lines): {skipped}")
    if args.dry_run:
        for e in events[:5]:
            print(f"- {e['timestamp']} {e['username']} {e['source_ip']} {e['status']}")
        return

    result = insert_raw_events(events, source_type="lab")
    print(f"Inserted: {result['inserted']}, Rejected: {result['rejected']}")
    for err in result["errors"]:
        print(" -", err)


if __name__ == "__main__":
    main()