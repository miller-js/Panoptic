#!/usr/bin/env bash
#
# One-command Panoptic bring-up:
#   1. start Elasticsearch + Kibana, wait for green/yellow health
#   2. build the ml-service / api / frontend images
#   3. train the anomaly model (into the ml_artifacts volume) if not present
#   4. start every service
#
# Re-runnable. Assumes filebeat-* data already exists in Elasticsearch (this
# repo does not ship the telemetry pipeline -- see README).
#
# Usage:
#   ./scripts/bootstrap.sh                 # normal
#   FAST_BACKFILL=1 ./scripts/bootstrap.sh # large batch / short loop for first run
#   RETRAIN=1 ./scripts/bootstrap.sh       # force model retrain

set -euo pipefail
cd "$(dirname "$0")/.."

compose() { docker compose "$@"; }

echo "==> Starting Elasticsearch + Kibana"
compose up -d elasticsearch kibana

echo "==> Waiting for Elasticsearch to be healthy"
for i in $(seq 1 60); do
  if curl -sf http://localhost:9200/_cluster/health >/dev/null 2>&1; then
    echo "    Elasticsearch is up"
    break
  fi
  sleep 3
  [ "$i" = 60 ] && { echo "    Elasticsearch did not come up in time"; exit 1; }
done

echo "==> Building images"
compose build ml-service api frontend

MODEL_PRESENT=$(compose run --rm --no-deps --entrypoint sh ml-service -c \
  'test -f /app/artifacts/model.pkl && echo yes || echo no' 2>/dev/null | tr -d '[:space:]' || echo no)

if [ "${RETRAIN:-0}" = "1" ] || [ "$MODEL_PRESENT" != "yes" ]; then
  echo "==> Training anomaly model (this reads a random sample of filebeat-* and may take a minute)"
  compose run --rm ml-service python train.py
else
  echo "==> Model already present in ml_artifacts volume (set RETRAIN=1 to force)"
fi

if [ "${FAST_BACKFILL:-0}" = "1" ]; then
  export PANOPTIC_BATCH_SIZE=8000
  export PANOPTIC_LOOP_INTERVAL=30
  echo "==> FAST_BACKFILL: batch=$PANOPTIC_BATCH_SIZE interval=${PANOPTIC_LOOP_INTERVAL}s"
fi

echo "==> Starting all services"
compose up -d

cat <<EOF

Panoptic is up:
  Dashboard      http://localhost:8081
  API            http://localhost:8080/api/alerts
  Kibana         http://localhost:5601
  Elasticsearch  http://localhost:9200

ml-service is scoring the filebeat-* backlog into panoptic-alerts now.
Watch progress:   docker compose logs -f ml-service
Score report:     docker compose run --rm ml-service python report.py
Model evaluation: docker compose run --rm ml-service python evaluate.py
EOF
