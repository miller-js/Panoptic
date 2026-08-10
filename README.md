# Panoptic (AI-Powered SIEM Platform)
Coming soon

The vision: 
```
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
  Python ML      MITRE ATT&CK     CVSS scores
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
```

Future:
- MITRE ATT&CK tagging
- CVSS-style risk scoring
- GeoIP mapping
- Authentication and Encryption (TLS)
