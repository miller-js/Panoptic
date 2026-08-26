import joblib

from sklearn.ensemble import IsolationForest

from elastic import ElasticClient
from parser import parse_message, extract_raw_audit_text
from features import engineer_features


elastic = ElasticClient()

logs = elastic.get_latest_logs(size=5000)

X = []

for log in logs:

    parsed = parse_message(extract_raw_audit_text(log))

    log["parsed"] = parsed

    features = engineer_features(log)

    X.append(features["ml"])


print(f"Training on {len(X)} events...")

model = IsolationForest(

    n_estimators=100,

    contamination=0.02,

    random_state=42

)

model.fit(X)

joblib.dump(model, "model.pkl")

print("Saved model.pkl")