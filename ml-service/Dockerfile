FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Model artifacts live in /app/artifacts. They are baked into the image at
# build time, but a volume can be mounted over this path to share a
# freshly-trained model without rebuilding (see docker-compose.yml).
ENV PANOPTIC_ARTIFACTS_DIR=/app/artifacts

# Scoring loop by default. Override the command to (re)train:
#   docker compose run --rm ml-service python train.py
CMD ["python", "main.py"]
