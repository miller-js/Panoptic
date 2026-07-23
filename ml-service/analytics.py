def summarize_event_types(logs, extract_features):
    """
    Counts how many events of each audit type contain useful fields.
    """

    summary = {}

    for log in logs:
        features = extract_features(log)

        event_type = features["audit_type"]

        if event_type is None:
            continue

        # Create the event type if we've never seen it
        if event_type not in summary:
            summary[event_type] = {
                "total": 0,
                "uid": 0,
                "auid": 0,
                "command": 0,
                "executable": 0,
                "result": 0,
            }

        summary[event_type]["total"] += 1

        if features["uid"] is not None:
            summary[event_type]["uid"] += 1

        if features["auid"] is not None:
            summary[event_type]["auid"] += 1

        if features["command"] is not None:
            summary[event_type]["command"] += 1

        if features["executable"] is not None:
            summary[event_type]["executable"] += 1

        if features["result"] is not None:
            summary[event_type]["result"] += 1

    return summary


def print_summary(summary):

    print("\n========== Audit Event Summary ==========\n")

    for event_type, stats in summary.items():

        total = stats["total"]

        print(f"{event_type}")
        print(f"  Total Events : {total}")
        print(f"  UID          : {stats['uid']}/{total}")
        print(f"  AUID         : {stats['auid']}/{total}")
        print(f"  Command      : {stats['command']}/{total}")
        print(f"  Executable   : {stats['executable']}/{total}")
        print(f"  Result       : {stats['result']}/{total}")
        print()