import joblib

from parser import parse_message
from features import engineer_features


class Predictor:

    def __init__(self):

        self.model = joblib.load("model.pkl")

    def predict(self, log):

        parsed = parse_message(log["message"])

        log["parsed"] = parsed

        features = engineer_features(log)

        vector = [features["ml"]]

        prediction = self.model.predict(vector)[0]

        raw_score = self.model.decision_function(vector)[0]

        risk_score = max(0, min(100, int((1 - raw_score) * 50)))

        return {

            "prediction": int(prediction),

            "risk_score": float(risk_score),

            #"features": features["display"]
        }