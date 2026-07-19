'''
while True:

    logs = elastic.get_new_logs()

    alerts = detector.analyze(logs)

    elastic.store_alerts(alerts)

    sleep(5)
'''

from elastic import ElasticClient

elastic = ElasticClient()

print(elastic.test_connection())