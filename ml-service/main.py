from elastic import ElasticClient
from predict import Predictor

elastic = ElasticClient()

predictor = Predictor()

logs = elastic.get_latest_logs(size=10)

for log in logs:

    result = predictor.predict(log)

    print(result)