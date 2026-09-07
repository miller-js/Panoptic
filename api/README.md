# Panoptic API

Go REST API over the `panoptic-alerts` Elasticsearch index (written by
`ml-service`).

Layering: `main.go` (routes + CORS) → `handlers.go` (HTTP: param parsing,
status codes) → `elastic/` (query bodies + response decoding). Handlers hold no
Elasticsearch knowledge; the `elastic` package builds no HTTP responses.

## Running

```bash
go run .
# or
docker compose up -d api
```

### Configuration

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `PANOPTIC_ES_ADDR` | `http://192.168.10.100:9200` | compose overrides to `http://elasticsearch:9200` |
| `PANOPTIC_ES_USER` / `PANOPTIC_ES_PASSWORD` | `elastic` / `changeme` | cluster security is disabled today; ignored server-side |
| `PANOPTIC_ALERTS_INDEX` | `panoptic-alerts` | index to read |
| `PANOPTIC_CORS_ORIGINS` | `*` | comma-separated allow-list; `*` echoes any origin |

## Endpoints

All `GET`, all JSON. Non-2xx bodies are `{"error": "..."}` — `400` invalid
param, `404` unknown id, `502` Elasticsearch failure.

### `GET /health` → `{"status":"ok"}`

### `GET /api/alerts`

Filterable / sortable / paginated alert list.

| Param | Type | Notes |
|---|---|---|
| `size` / `from` | int | page size (≤100, default 20) / offset |
| `sort_by` | enum | `risk_score` (default), `detected_at`, `event_time` |
| `order` | enum | `desc` (default), `asc` |
| `severity` | csv | any of `informational,low,medium,high,critical` |
| `min_risk_score` / `max_risk_score` | number | on `risk.score` |
| `min_anomaly_score` | number | on `detection.anomaly_score` |
| `anomaly` | bool | only IsolationForest label `-1` |
| `host` | string | exact `host.name` |
| `user` | string | matches `user.name` or `user.audit_name` |
| `event_type` | string | exact `event.type` (e.g. `SYSCALL`), upper-cased |
| `technique` | string | exact `mitre.technique_id` (e.g. `T1059.004`) |
| `from_time` / `to_time` | RFC3339 or `YYYY-MM-DD` | range on `event.timestamp` |
| `q` | string | full-text over explanation, command line, raw event |

Response: `{ "total": <int>, "items": [ <alert>, ... ] }` — alert shape is the
`panoptic-alerts` document (see repo README) plus a top-level `id`.

### `GET /api/alerts/{id}` → one alert, `404` if absent.

### `GET /api/alerts/stats`  (also `GET /api/stats`)

```json
{ "total", "anomaly_count", "avg_risk_score", "max_risk_score",
  "by_severity": { "low": …, "high": … }, "last_24h" }
```

### `GET /api/anomalies/timeline`

`interval` ∈ `5m,15m,1h,3h,12h,1d` (default `1h`); optional `from_time`/`to_time`
(no default window — spans the data if unset). Returns
`{ "interval", "buckets": [ { "timestamp", "total", "anomalies", "high_or_critical" } ] }`.

### `GET /api/risk/distribution`

`{ "total", "bands": [ { "key", "severity", "from", "to", "count" } ] }` — always
the five severity bands, zero-filled.

### `GET /api/mitre/techniques`

Optional `from_time`/`to_time`, `size` (≤50). Returns
`{ "techniques": [ { "technique_id", "technique_name", "tactic", "count", "max_confidence" } ] }`,
count-descending.

### Legacy: `GET /api/logs`, `GET /api/logs/{id}`

The pre-2.0 response shape (`prediction`, `risk_score`, `audit_type`, `message`,
`log`, …), served from `panoptic-alerts` so old consumers keep working. Params:
`size`, `from`, `sort_by` (`timestamp`|`risk_score`), `order`, `min_risk_score`,
`anomaly`, `audit_type`, `q`. Prefer `/api/alerts` for new work.

## Tests

`go test ./...` — handler status codes / param validation and the Elasticsearch
query layer, both against a stubbed `http.RoundTripper` (no cluster needed).

## Known limitations

* No auth on the API; CORS defaults to `*`. Lock down before any exposure.
* `from`/`size` pagination is capped by Elasticsearch's 10 000-result window —
  switch to `search_after` if deep pagination is ever needed.
