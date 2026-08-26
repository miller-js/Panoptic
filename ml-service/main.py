import time

from elastic import ElasticClient
from predict import Predictor
from features import engineer_features
from parser import parse_message

elastic = ElasticClient()

predictor = Predictor()

while True:

    logs = elastic.get_unprocessed_logs(size=1000)

    for log in logs:

        result = predictor.predict(log)

        # New prediction log is stored in Elasticsearch
        elastic.store_prediction(
            original_log=log,
            prediction=result["prediction"],
            risk_score=result["risk_score"],
            model="IsolationForest-v1"
        )
    
    time.sleep(300)