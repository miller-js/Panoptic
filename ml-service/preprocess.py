from datetime import datetime

def parse_message(message):
    """
    Helper function for extract_features.
    Cleans up log and turns it into a dictionary.
    """

    parsed = {}

    for part in message.split():

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        parsed[key] = value.strip("\"'")

    return parsed

def extract_features(log: dict) -> dict:
    """
    Convert a raw Elasticsearch log into a smaller feature dictionary.
    """

    parsed = parse_message(log.get("message", ""))

    # Parse timestamp
    ts = log.get("@timestamp")
    hour = None
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
        except Exception:
            pass

    return {
        "timestamp": ts,
        "hour": hour,
        "hostname": log.get("host", {}).get("hostname"),
        "audit_type": parsed.get("type"),
        "uid": parsed.get("uid"),
        "auid": parsed.get("auid"),
        "command": parsed.get("comm"),
        "executable": parsed.get("exe"),
        "result": parsed.get("res"),
        "is_root": parsed.get("uid") == "0",
    }