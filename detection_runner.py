
from datetime import timedelta

from dotenv import load_dotenv

from db import get_db_connection
from rules import detect_brute_force
from risk import score_brute_force
from incident_store import save_detections

load_dotenv()

SUCCESS_WINDOW_MINUTES = 10


def load_login_events():
    conn = get_db_connection()

    if not conn:
        return None

    cursor = None

    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT event_id, timestamp, username, source_ip,
                   event_type, status
            FROM security_events
            WHERE event_type = %s
            ORDER BY timestamp
            """,
            ("LOGIN",),
        )

        return cursor.fetchall()

    except Exception as e:
        print(f"Load error: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        conn.close()


def has_success_after(
    detection,
    events,
    minutes=SUCCESS_WINDOW_MINUTES,
):
    end = detection["last_seen"] + timedelta(minutes=minutes)

    for event in events:
        if (
            event["source_ip"] == detection["source_ip"]
            and event["status"] == "SUCCESS"
            and detection["last_seen"]
            <= event["timestamp"]
            <= end
        ):
            return True

    return False


def run_brute_force_detection(threshold=5, window_minutes=10):
    events = load_login_events()

    if events is None:
        return None

    detections = detect_brute_force(
        events,
        threshold=threshold,
        window_minutes=window_minutes,
    )

    for detection in detections:
        detection["risk"] = score_brute_force(
            detection["failed_attempts"],
            detection["first_seen"],
            success_after=has_success_after(detection, events),
        )

    return detections


if __name__ == "__main__":
    detections = run_brute_force_detection()

    if detections is None:
        raise SystemExit("Could not load events from the database.")

    print(f"Brute-force detections: {len(detections)}")

    for detection in detections:
        risk = detection["risk"]

        print(
            f"- {detection['rule']} | "
            f"ip={detection['source_ip']} | "
            f"users={detection['usernames']} | "
            f"attempts={detection['failed_attempts']} | "
            f"{detection['first_seen']} -> {detection['last_seen']} | "
            f"risk={risk['score']} ({risk['level']})"
        )

        for factor in risk["factors"]:
            print(f"    +{factor['points']}  {factor['factor']}")

    saved = save_detections(detections)

    if saved is None:
        raise SystemExit("Could not save incidents.")

    print(
        f"Incidents created: {saved['created']} | "
        f"skipped (already saved, risk refreshed): {saved['skipped']}"
    )