from db import get_db_connection
from normalizer import normalize_event, EVENT_FIELDS

# Column names come from a fixed constant (never user input); values are parameterized.
INSERT_SQL = (
    "INSERT INTO security_events ("
    + ", ".join(f"`{f}`" for f in EVENT_FIELDS)
    + ") VALUES ("
    + ", ".join(["%s"] * len(EVENT_FIELDS))
    + ")"
)


def insert_raw_events(raw_records, source_type="synthetic"):
    """
    Normalize and insert a list of raw dict records.
    Returns {"inserted": int, "rejected": int, "errors": [str, ...]}.
    Invalid records are skipped; a database failure rolls back the whole batch.
    """
    rows = []
    errors = []
    rejected = 0

    for index, raw in enumerate(raw_records):
        event, err = normalize_event(raw, source_type=source_type)
        if err:
            rejected += 1
            if len(errors) < 20:
                errors.append(f"Record {index}: {err}")
            continue
        rows.append(tuple(event[f] for f in EVENT_FIELDS))

    result = {"inserted": 0, "rejected": rejected, "errors": errors}
    if not rows:
        return result

    conn = get_db_connection()
    if not conn:
        result["errors"].append("Database unavailable; nothing inserted.")
        result["rejected"] += len(rows)
        return result

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.executemany(INSERT_SQL, rows)
        conn.commit()
        result["inserted"] = len(rows)
    except Exception as e:
        conn.rollback()
        result["errors"].append(f"Database error: {e}")
        result["rejected"] += len(rows)
    finally:
        if cursor:
            cursor.close()
        conn.close()

    return result