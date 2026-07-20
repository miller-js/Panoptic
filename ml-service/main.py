'''
while True:

    logs = elastic.get_new_logs()

    alerts = detector.analyze(logs)

    elastic.store_alerts(alerts)

    sleep(5)
'''
from elastic import ElasticClient
from preprocess import extract_features

elastic = ElasticClient()

logs = elastic.get_latest_logs(size=20)

# log = logs[0]
# print("Before extract features: ")
# print(log)

for log in logs:
    features = extract_features(log)
    print(features)