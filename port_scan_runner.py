from dotenv import load_dotenv

from rules import detect_port_scan
from risk import score_port_scan
from incident_store import save_detections
from check_port_scan_rule import load_network_events

load_dotenv()


def count_open_ports(detection, events_by_id):
    """Number of distinct probed ports whose connection succeeded."""
    open_ports = set()
    for eid in detection["event_ids"]:
        e = events_by_id.get(eid)
        if e and e["status"] == "SUCCESS":
            open_ports.add(e["destination_port"])
    return len(open_ports)


def run_port_scan_detection(port_threshold=10, window_seconds=120):
    """Return port-scan detections, each with a 'risk' dict (None on DB failure)."""
    events = load_network_events()
    if events is None:
        return None
    events_by_id = {e["event_id"]: e for e in events}
    detections = detect_port_scan(events, port_threshold=port_threshold,
                                  window_seconds=window_seconds)
    for d in detections:
        d["open_ports_found"] = count_open_ports(d, events_by_id)
        d["risk"] = score_port_scan(d["distinct_ports"], d["first_seen"],
                                    open_ports_found=d["open_ports_found"])
    return detections


if __name__ == "__main__":
    detections = run_port_scan_detection()
    if detections is None:
        raise SystemExit("Could not load events from the database.")

    print(f"Port scan detections: {len(detections)}")
    for d in detections:
        print(f"- {d['rule']} | src={d['source_ip']} -> dst={d['destination_ip']} | "
              f"ports={d['distinct_ports']} | open={d['open_ports_found']} | "
              f"{d['first_seen']} -> {d['last_seen']} | "
              f"risk={d['risk']['score']} ({d['risk']['level']})")
        for f in d["risk"]["factors"]:
            print(f"    +{f['points']}  {f['factor']}")

    saved = save_detections(detections)
    if saved is None:
        raise SystemExit("Could not save incidents.")
    print(f"Incidents created: {saved['created']} | skipped (already saved, risk refreshed): {saved['skipped']}")