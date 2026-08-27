# Panoptic

An AI-powered SIEM (security information and event management) pipeline, built as a
learning project to develop security-focused software engineering skills.

Linux auditd logs are shipped by Filebeat into Elasticsearch, scored for anomalies by
a Python ML service, and served through a Go REST API to a React dashboard.

```
                Linux (auditd)
                      │
                   Filebeat
                      │
                      ▼
               Elasticsearch
          (raw security telemetry)
                      │
                      ▼
              ml-service (Python)
         IsolationForest anomaly scoring
                      │
                      ▼
               Elasticsearch
        (enriched alerts & detections)
                      │
                      ▼
                 Go REST API
                      │
                      ▼
                  React UI
```

## Components

| Component | Stack | What it does |
|---|---|---|
| [`ml-service/`](ml-service) | Python, scikit-learn | Pulls unprocessed logs from `filebeat-*`, scores them with an IsolationForest model, writes predictions to `panoptic-predictions`. |
| [`api/`](api/README.md) | Go | REST API over `panoptic-predictions` — paginated/filterable/sortable log listing, single-log lookup, summary stats. |
| [`frontend/`](frontend/README.md) | React + Vite | Dashboard: stats bar, sortable/filterable log table, row expansion for full log detail. |

Each subdirectory has its own README with setup, configuration, and API/endpoint
details. `docker-compose.yml` at the repo root brings up Elasticsearch and Kibana;
each component's own `Dockerfile` builds that service.

## Status

The full pipeline above is built and working end-to-end against a real dataset
(~320k Linux auditd documents).

Not yet built:

- [ ] MITRE ATT&CK tagging and CVSS-style risk scoring
- [ ] LLM-generated, verbose/actionable alert summaries
- [ ] End-to-end encryption and authentication (Elasticsearch and the API
      currently run without auth/TLS)
- [ ] Live updates (WebSocket push instead of manual refresh)
- [ ] Kubernetes deployment in AWS

## Development note

Portions of this project (including debugging, the Go API, and the React frontend)
were built with the help of an agentic coding assistant (Claude Code). Design
decisions, review, and verification were done by the project owner.
