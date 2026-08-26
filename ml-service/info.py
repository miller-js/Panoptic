from elastic import ElasticClient

elastic = ElasticClient()

logs = elastic.get_processed_logs(size=5)

for log in logs:
    print("--------------------------------")
    print("Document ID:", log["id"])
    print("Index:", log["index"])
    print("Document:")
    print(log["source"])