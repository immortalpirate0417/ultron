from dotenv import load_dotenv

from rules import detect_privilege_change
from risk import score_privilege_change
from incident_store import save_detections
from check_privilege_rule import load_privilege_events
from volume_runner import load_first_ip_use, is_new_source_ip

load_dotenv()


def run_privilege_change_detection():
    """Return privilege-change detections, each with a 'risk' dict (None on DB failure)."""
    events = load_privilege_events()
    first_ip_use = load_first_ip_use()
    if events is None or first_ip_use is None:
        return None
    detections = detect_privilege_change(events)
    for d in detections:
        d["new_source_ip"] = is_new_source_ip(d, first_ip_use)
        d["risk"] = score_privilege_change(
            d["privilege_level"], d["timestamp"], new_source_ip=d["new_source_ip"]
        )
    return detections


if __name__ == "__main__":
    detections = run_privilege_change_detection()
    if detections is None:
        raise SystemExit("Could not load events from the database.")

    print(f"Privilege change detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | user={d['username']} | ip={d['source_ip']} | "
              f"time={d['timestamp']} | level={d['privilege_level']} | "
              f"new_ip={d['new_source_ip']} | "
              f"risk={d['risk']['score']} ({d['risk']['level']})")
        for f in d["risk"]["factors"]:
            print(f"    +{f['points']}  {f['factor']}")

    saved = save_detections(detections)
    if saved is None:
        raise SystemExit("Could not save incidents.")
    print(f"Incidents created: {saved['created']} | skipped (already saved, risk refreshed): {saved['skipped']}")