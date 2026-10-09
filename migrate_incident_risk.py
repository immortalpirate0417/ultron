
from dotenv import load_dotenv
from db import get_db_connection

load_dotenv()

COLUMNS = {
    "risk_score": "INT NULL",
    "risk_level": "VARCHAR(10) NULL",
    "risk_factors": "JSON NULL",
}

conn = get_db_connection()

if not conn:
    raise SystemExit("Could not connect to database.")

cursor = None

try:
    cursor = conn.cursor()

    for name, definition in COLUMNS.items():
        cursor.execute(
            "SELECT COUNT(*) FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() "
            "AND TABLE_NAME = %s AND COLUMN_NAME = %s",
            ("incidents", name)
        )

        if cursor.fetchone()[0]:
            print(f"{name}: already exists")
        else:
            cursor.execute(
                f"ALTER TABLE incidents ADD COLUMN {name} {definition}"
            )
            print(f"{name}: added")

    conn.commit()
    print("Incident risk migration completed.")

except Exception as e:
    conn.rollback()
    raise SystemExit(f"Migration failed: {e}")

finally:
    if cursor:
        cursor.close()
    conn.close()