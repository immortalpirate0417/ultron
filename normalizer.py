import ipaddress
import json
from datetime import datetime

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%m/%Y %H:%M:%S",
)

EVENT_FIELDS = (
    "timestamp", "username", "source_ip", "destination_ip",
    "source_port", "destination_port", "device_id", "event_type",
    "action", "status", "resource", "privilege_level",
    "bytes_transferred", "raw_log", "severity", "source_type", "metadata",
)


def _clean_str(value, max_len):
    """Return a trimmed string cut to max_len, or None if empty/missing."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


def _parse_timestamp(value):
    """Return a datetime, or None if it cannot be parsed."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = _clean_str(value, 40)
    if not text:
        return None
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _parse_ip(value):
    """Return a valid IP string, or None."""
    text = _clean_str(value, 45)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _parse_port(value):
    """Return an int port 0-65535, or None."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _parse_bytes(value):
    """Return a non-negative int, or None."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _parse_metadata(value):
    """Return a JSON string for the metadata column, or None."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            json.loads(value)
            return value
        except ValueError:
            return json.dumps({"note": value})
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return None


def normalize_event(raw, source_type="synthetic"):
    """
    Convert one raw record (dict) into the security_events structure.
    Returns (event_dict, None) on success, or (None, error_message) if the
    record is unusable (missing/invalid timestamp or event_type).
    """
    if not isinstance(raw, dict):
        return None, "Record is not a dictionary"

    timestamp = _parse_timestamp(raw.get("timestamp"))
    if timestamp is None:
        return None, "Missing or invalid timestamp"

    event_type = _clean_str(raw.get("event_type"), 50)
    if event_type is None:
        return None, "Missing event_type"
    event_type = event_type.upper()

    severity = (_clean_str(raw.get("severity"), 10) or "INFO").upper()
    if severity not in VALID_SEVERITIES:
        severity = "INFO"

    status = _clean_str(raw.get("status"), 20)
    action = _clean_str(raw.get("action"), 50)

    event = {
        "timestamp": timestamp,
        "username": _clean_str(raw.get("username"), 50),
        "source_ip": _parse_ip(raw.get("source_ip")),
        "destination_ip": _parse_ip(raw.get("destination_ip")),
        "source_port": _parse_port(raw.get("source_port")),
        "destination_port": _parse_port(raw.get("destination_port")),
        "device_id": _clean_str(raw.get("device_id"), 50),
        "event_type": event_type,
        "action": action.upper() if action else None,
        "status": status.upper() if status else None,
        "resource": _clean_str(raw.get("resource"), 255),
        "privilege_level": _clean_str(raw.get("privilege_level"), 20),
        "bytes_transferred": _parse_bytes(raw.get("bytes_transferred")),
        "raw_log": _clean_str(raw.get("raw_log"), 65000),
        "severity": severity,
        "source_type": _clean_str(source_type, 20) or "synthetic",
        "metadata": _parse_metadata(raw.get("metadata")),
    }
    return event, None