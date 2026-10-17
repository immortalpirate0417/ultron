from dotenv import load_dotenv

from detection_runner import run_brute_force_detection
from stat_runner import run_unusual_login_hour_detection
from volume_runner import run_unusual_data_volume_detection
from incident_store import save_detections

load_dotenv()

# Each entry: (label, function returning a list of detections or None on DB failure)
DETECTORS = [
    ("Brute force", run_brute_force_detection),
    ("Unusual login hour", run_unusual_login_hour_detection),
    ("Unusual data volume", run_unusual_data_volume_detection),
]


def run_all():
    """Run all detectors and save the results. Returns a summary dict, or None on failure."""
    all_detections = []
    per_detector = {}

    for label, runner in DETECTORS:
        detections = runner()
        if detections is None:
            print(f"{label}: could not load events from the database.")
            return None
        per_detector[label] = len(detections)
        all_detections.extend(detections)

    saved = save_detections(all_detections)
    if saved is None:
        print("Could not save incidents.")
        return None

    return {"per_detector": per_detector, "created": saved["created"],
            "skipped": saved["skipped"]}


if __name__ == "__main__":
    summary = run_all()
    if summary is None:
        raise SystemExit(1)

    print("Detections found:")
    for label, count in summary["per_detector"].items():
        print(f"  {label}: {count}")
    print(f"Incidents created: {summary['created']}")
    print(f"Already saved (risk refreshed): {summary['skipped']}")