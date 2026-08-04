from elastic import ElasticClient
from predict import Predictor
from features import engineer_features
from parser import parse_message

elastic = ElasticClient()

predictor = Predictor()

while True:

    logs = elastic.get_latest_logs()

    for log in logs:

        prediction, score = predictor.predict(log)

        # New prediction log is stored in Elasticsearch
        elastic.store_prediction(
            original_log=log,
            prediction=prediction,
            risk_score=score,
            model="IsolationForest-v1"
        )
    
    time.sleep(300)