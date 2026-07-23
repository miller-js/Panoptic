from datetime import datetime

def engineer_features(log):
    """
    Converts an Elasticsearch Auditd log into a feature vector
    that can later be fed into an ML model.
    """

    # Raw parsed audit fields
    parsed = log["parsed"]

    timestamp = log.get("@timestamp")
    hostname = log.get("host", {}).get("hostname")

    # -------------------------
    # Time Features
    # -------------------------

    hour = None
    day_of_week = None
    is_weekend = False
    is_business_hours = False

    if timestamp:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        hour = dt.hour
        day_of_week = dt.weekday()      # Monday = 0

        is_weekend = day_of_week >= 5
        is_business_hours = 8 <= hour <= 17

    # -------------------------
    # User Features
    # -------------------------

    uid = parsed.get("uid")
    auid = parsed.get("auid")

    is_root = uid == "0"

    # -------------------------
    # Process Features
    # -------------------------

    command = parsed.get("comm")
    executable = parsed.get("exe")

    command_length = len(command) if command else 0

    executable_depth = 0

    if executable:
        executable_depth = executable.count("/")

    # -------------------------
    # Event Features
    # -------------------------

    audit_type = parsed.get("type")

    result = parsed.get("res")

    success = result == "success"

    # -------------------------
    # Feature Vector
    # -------------------------

    features = {

        # Time
        "hour": hour,
        "day_of_week": day_of_week,
        "is_weekend": is_weekend,
        "is_business_hours": is_business_hours,

        # Host
        "hostname": hostname,

        # User
        "uid": uid,
        "auid": auid,
        "is_root": is_root,

        # Process
        "command": command,
        "command_length": command_length,
        "executable": executable,
        "executable_depth": executable_depth,

        # Event
        "audit_type": audit_type,
        "result": result,
        "success": success
    }

    return features