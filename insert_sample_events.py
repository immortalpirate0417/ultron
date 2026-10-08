from dotenv import load_dotenv
from db import get_db_connection
from event_store import insert_raw_events

load_dotenv()

SAMPLE = [
    {"timestamp": "2025-01-15 09:05:00", "username": "alice", "source_ip": "192.168.1.10",
     "device_id": "LAPTOP-01", "event_type": "login", "status": "success", "severity": "info"},
    {"timestamp": "2025-01-15 02:31:00", "username": "bob", "source_ip": "10.0.0.50",
     "destination_port": 22, "event_type": "login", "status": "failure", "severity": "medium",
     "metadata": {"reason": "bad password", "simulated": True}},
    {"timestamp": "2025-01-15 11:00:00", "username": "alice", "event_type": "file_access",
     "resource": "/data/reports.xlsx", "bytes_transferred": 20480},
    {"timestamp": "not a date", "event_type": "login"},  # invalid on purpose
]

# Clear earlier test rows so this script can be re-run safely.
conn = get_db_connection()
if not conn:
    raise SystemExit("Could not connect to database.")
cursor = conn.cursor()
cursor.execute("DELETE FROM security_events WHERE source_type = %s", ("test",))
conn.commit()

result = insert_raw_events(SAMPLE, source_type="test")
print(f"Inserted: {result['inserted']}, Rejected: {result['rejected']}")
for e in result["errors"]:
    print(" -", e)

cursor.execute("SELECT COUNT(*) FROM security_events WHERE source_type = %s", ("test",))
print("Test rows in database:", cursor.fetchone()[0])
cursor.close()
conn.close()