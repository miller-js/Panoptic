'''
while True:

    logs = elastic.get_new_logs()

    alerts = detector.analyze(logs)

    elastic.store_alerts(alerts)

    sleep(5)
'''
from elastic import ElasticClient
from parser import parse_message
from features import engineer_features


def main():

    elastic = ElasticClient()

    logs = elastic.get_latest_logs(size=20)

    for log in logs:

        # Step 1: Parse the raw Auditd message
        parsed = parse_message(log["message"])

        # Save the parsed data inside the log
        log["parsed"] = parsed

        # Step 2: Engineer ML features
        features = engineer_features(log)

        # Step 3: Display them
        print("--------------------------------")
        print(features)


if __name__ == "__main__":
    main()