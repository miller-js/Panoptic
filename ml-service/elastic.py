'''
This file knows everything about Elasticsearch.
None of the other files need to care how Elasticsearch works
'''

from elasticsearch import Elasticsearch
from datetime import datetime, timezone

# Represent Elasticsearch as a class
class ElasticClient:
    def __init__(self):
        self.es = Elasticsearch(
            "http://192.168.10.100:9200",
            basic_auth=("elastic", "changeme")
        )

    def test_connection(self):
        return self.es.info()

    def get_latest_logs(self, size=10):
    # Gets only the last 10 logs, returns them as a list of dictionaries,
    # each being a log with only the source_ field.
        response = self.es.search(
            index="filebeat-*",
            size=size,
            sort=[
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            query={
                "match_all": {}
            }
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def get_logs_by_type(self, audit_type, size=100):
        response = self.es.search(
            index="filebeat-*",
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}],
            query={
                "match": {
                    "message": f"type={audit_type}"
                }
            }
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def store_prediction(self, original_log, prediction, risk_score,
                         confidence=None, model="baseline"):

        document = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "model": model,
            "prediction": prediction,
            "risk_score": risk_score,
            "confidence": confidence,
            "log": original_log
        }

        return self.es.index(
            index="panoptic-predictions",
            document=document
        )