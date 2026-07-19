'''
while True:

    logs = elastic.get_new_logs()

    alerts = detector.analyze(logs)

    elastic.store_alerts(alerts)

    sleep(5)
'''

from elastic import ElasticClient

elastic = ElasticClient()

logs = elastic.get_latest_logs()

for log in logs:
    print(log.keys())