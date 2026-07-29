from datetime import datetime


def engineer_features(log):

    parsed = log["parsed"]

    timestamp = log.get("@timestamp")
    hostname = log.get("host", {}).get("hostname")

    # -----------------
    # Time
    # -----------------

    hour = 0
    day = 0
    weekend = 0
    business = 0

    if timestamp:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        hour = dt.hour
        day = dt.weekday()

        weekend = int(day >= 5)
        business = int(8 <= hour <= 17)

    # -----------------
    # User
    # -----------------

    uid = parsed.get("uid")

    try:
        uid = int(uid)
    except:
        uid = -1

    auid = parsed.get("auid")

    try:
        auid = int(auid)
    except:
        auid = -1

    is_root = int(uid == 0)

    # -----------------
    # Process
    # -----------------

    command = parsed.get("comm")

    executable = parsed.get("exe")

    command_length = len(command) if command else 0

    executable_depth = executable.count("/") if executable else 0

    # -----------------
    # Event
    # -----------------

    audit_type = parsed.get("type")

    result = parsed.get("res")

    success = int(result == "success")

    # -----------------
    # Numeric ML vector
    # -----------------

    ml = [

        hour,
        day,
        weekend,
        business,

        uid,
        auid,
        is_root,

        command_length,
        executable_depth,

        success
    ]

    # -----------------
    # Human-readable info
    # -----------------

    display = {

        "hostname": hostname,

        "command": command,

        "executable": executable,

        "audit_type": audit_type,

        "result": result
    }

    return {

        "ml": ml,

        "display": display
    }