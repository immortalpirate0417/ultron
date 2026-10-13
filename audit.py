
from db import get_db_connection

INCIDENT_ACTIONS = ("INCIDENT_STATUS", "INCIDENT_NOTE")


def log_audit(action, status, user_id=None, username=None, ip_address=None, details=None):
    """Insert one audit record. Never raises: auditing must not break the app."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            print("Audit log skipped: no database connection.")
            return
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (user_id, username, action, status, ip_address, details) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, username, action, status, ip_address, details)
        )
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"Audit log error: {e}")
    finally:
        if conn and conn.is_connected():
            conn.close()


def get_incident_audit_history(incident_id):
    """
    Return audit rows for one incident, newest first (empty list if none or on failure).
    Matches details that start with 'incident_id=<id>:' so id 1 never matches id 10.
    """
    prefix = f"incident_id={int(incident_id)}:"
    conn = get_db_connection()
    if not conn:
        return []

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT username, action, status, details, created_at FROM audit_logs "
            "WHERE action IN (%s, %s) AND LEFT(details, CHAR_LENGTH(%s)) = %s "
            "ORDER BY created_at DESC, id DESC",
            (INCIDENT_ACTIONS[0], INCIDENT_ACTIONS[1], prefix, prefix)
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"Audit history error: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        conn.close()
