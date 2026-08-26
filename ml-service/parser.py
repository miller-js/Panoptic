def extract_raw_audit_text(log):
    """
    Filebeat ingests this data two ways: a raw filestream tailing
    /var/log/audit/audit.log (puts the audit line in `message`), and the
    auditd module (puts the same line in `event.original` instead and
    never sets `message`). Both contain the same key=value audit text.
    """
    return log.get("message") or log.get("event", {}).get("original", "")


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
