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

    def get_unprocessed_logs(self, size=10):
    # Advances forward through filebeat-* in @timestamp order, picking up
    # after the last log we already scored (per panoptic-predictions).
    # Without this, "latest N" against a static/historical dataset would
    # just re-score the same N documents forever and never reach the rest
    # of the backlog.
        cursor_response = self.es.search(
            index="panoptic-predictions",
            size=1,
            sort=[{"log.@timestamp": {"order": "desc"}}],
            query={"match_all": {}}
        )

        cursor_hits = cursor_response["hits"]["hits"]

        if cursor_hits:
            query = {
                "range": {
                    "@timestamp": {
                        "gt": cursor_hits[0]["_source"]["log"]["@timestamp"]
                    }
                }
            }
        else:
            query = {"match_all": {}}

        response = self.es.search(
            index="filebeat-*",
            size=size,
            sort=[
                {"@timestamp": {"order": "asc"}},
                {"_seq_no": {"order": "asc"}}
            ],
            query=query
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

    def get_processed_logs(self, size=10):
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
                "exists": {
                    "field": "ml.risk_score"
                }
            }
        )

        return [
            {
                "id": hit["_id"],
                "index": hit["_index"],
                "source": hit["_source"]
            }
            for hit in response["hits"]["hits"]
        ]