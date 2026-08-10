# Panoptic (AI-Powered SIEM Platform) | Coming Soon
This project is for developing my security-focused software engineering skills and learning key concepts in the security industry.

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
   React UI                      External API
```

Future:
- [ ] Polished ETL service
    - [ ] MITRE ATT&CK tagging
    - [ ] CVSS-style risk scoring
    - [ ] Verbose and actionable alerts using LLM
- [ ] End-to-end encryption and authentication
- [ ] Polished API and dashboard
    - [ ] Live WebSocket updates
- [ ] Kubernetes deployment in AWS
