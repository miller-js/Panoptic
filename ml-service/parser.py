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
