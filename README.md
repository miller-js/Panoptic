# Panoptic
Coming soon

The vision:
                Windows/Linux
                      │
                  Filebeat
                      │
                      ▼
               Elasticsearch
          (raw security telemetry)
                      │
      ┌───────────────┼────────────────┐
      │               │                │
      ▼               ▼                ▼
 Python ML      Rule Engine      Threat Intel
  Service        (future)          (future)
      │               │                │
      └───────────────┼────────────────┘
                      ▼
              Elasticsearch
      (enriched alerts & detections)
                      │
                      ▼
                 Go REST API
                      │
      ┌───────────────┴───────────────┐
      ▼                               ▼
   React UI                     External API
