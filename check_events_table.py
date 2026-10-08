from db import get_db_connection
from dotenv import load_dotenv

load_dotenv()

conn = get_db_connection()
if not conn:
    print("Could not connect to database.")
else:
    cursor = conn.cursor()
    cursor.execute("DESCRIBE security_events")
    for row in cursor.fetchall():
        print(row[0], "-", row[1])
    cursor.close()
    conn.close()