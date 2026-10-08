from db import get_db_connection


def log_audit(
    action,
    status,
    user_id=None,
    username=None,
    ip_address=None,
    details=None
):
    """Insert one audit record. Never raises: auditing must not break the app."""
    conn = None

    try:
        conn = get_db_connection()

        if not conn:
            print("Audit log skipped: no database connection.")
            return

        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO audit_logs "
            "(user_id, username, action, status, ip_address, details) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (
                user_id,
                username,
                action,
                status,
                ip_address,
                details
            )
        )

        conn.commit()
        cursor.close()

    except Exception as e:
        print(f"Audit log error: {e}")

    finally:
        if conn and conn.is_connected():
            conn.close()