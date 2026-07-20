'''
This file knows everything about Elasticsearch.

get_new_logs()

store_alert()

connect()

None of the other files need to care how Elasticsearch works
'''

from elasticsearch import Elasticsearch

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