import argparse
import re
from datetime import datetime

from dotenv import load_dotenv

from event_store import insert_raw_events

load_dotenv()

# Traditional syslog format:
# Jan 15 02:31:07 labvm sshd[1234]: Failed password for bob from 10.0.0.5 port 51234 ssh2
LEGACY_LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:-session)?\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+\w+\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

# ISO timestamp format used by newer Ubuntu releases:
# 2026-10-25T08:33:04.550564-07:00 Vinhcent sshd-session[3257]: Failed password for vindant from 127.0.0.1 port 58482 ssh2
ISO_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd(?:-session)?\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+\w+\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_line(line, year):
    """Parse a supported SSH login line into a raw event, or return None."""
    line = line.strip()

    match = ISO_LINE_RE.match(line)
    timestamp = None

    if match:
        try:
            timestamp = datetime.fromisoformat(
                match["timestamp"].replace("Z", "+00:00")
            ).replace(tzinfo=None)
        except ValueError:
            return None
    else:
        match = LEGACY_LINE_RE.match(line)
        if not match:
            return None

        try:
            timestamp = datetime.strptime(
                f"{year} {match['mon']} {match['day']} {match['time']}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None

    success = match["result"] == "Accepted"

    return {
        "timestamp": timestamp,
        "username": match["user"],
        "source_ip": match["ip"],
        "source_port": match["port"],
        "destination_port": 22,
        "device_id": match["host"],
        "event_type": "LOGIN",
        "action": "LOGIN",
        "status": "SUCCESS" if success else "FAILURE",
        "severity": "INFO" if success else "LOW",
        "raw_log": line,
        "metadata": {"source": "auth.log", "lab": True},
    }


def parse_file(path, year):
    """Return (events, skipped_count) for an auth.log file."""
    events, skipped = [], 0

    with open(path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            if not line.strip():
                continue

            event = parse_line(line, year)
            if event:
                events.append(event)
            else:
                skipped += 1

    return events, skipped


def main():
    parser = argparse.ArgumentParser(
        description="Parse a Linux auth.log into ULTRON events."
    )
    parser.add_argument("path", help="Path to a copy of auth.log from your own VM")
    parser.add_argument("--year", type=int, default=datetime.now().year)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and report without inserting",
    )
    args = parser.parse_args()

    events, skipped = parse_file(args.path, args.year)
    print(f"Parsed: {len(events)}, skipped (unsupported lines): {skipped}")

    if args.dry_run:
        for event in events[:5]:
            print(
                f"- {event['timestamp']} {event['username']} "
                f"{event['source_ip']} {event['status']}"
            )
        return

    result = insert_raw_events(events, source_type="lab")
    print(f"Inserted: {result['inserted']}, Rejected: {result['rejected']}")

    for error in result["errors"]:
        print(" -", error)


if __name__ == "__main__":
    main()
