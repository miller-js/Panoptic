# Panoptic API

A Go REST API that serves ML-enhanced logs out of the `panoptic-predictions`
Elasticsearch index (written by `ml-service`). See `/home/stickyrice/Panoptic/CLAUDE.md`
for how that index's schema was derived and what data quirks it has.

## Running

```
go run .
```

Or via Docker:

```
docker build -t panoptic-api .
docker run --network host -e PORT=8080 panoptic-api
```

### Configuration (environment variables)

| Variable                | Default                    | Notes                                          |
|--------------------------|-----------------------------|-------------------------------------------------|
| `PORT`                   | `8080`                      | HTTP listen port                                |
| `PANOPTIC_ES_ADDR`       | `http://192.168.10.100:9200`| Matches ml-service's hardcoded Elasticsearch host |
| `PANOPTIC_ES_USER`       | `elastic`                   | Cluster security is currently disabled; ignored server-side today |
| `PANOPTIC_ES_PASSWORD`   | `changeme`                  | Same as above |

## Endpoints

All responses are JSON. All endpoints are `GET` only for this first pass.

### `GET /health`

Liveness check.

```json
{ "status": "ok" }
```

### `GET /api/logs`

Paginated, filterable, sortable list of ML-enhanced logs.

**Query parameters** (all optional):

| Param            | Type    | Default      | Notes                                                    |
|-------------------|---------|--------------|-----------------------------------------------------------|
| `size`            | int     | `20`         | Page size, clamped to 100                                 |
| `from`            | int     | `0`          | Offset for pagination                                     |
| `sort_by`         | string  | `timestamp`  | `timestamp` or `risk_score`                                |
| `order`           | string  | `desc`       | `asc` or `desc`                                            |
| `min_risk_score`  | float   | —            | Only logs with `risk_score >= min_risk_score`             |
| `anomaly`         | bool    | —            | `true` returns only `prediction == -1` (flagged anomalies) |
| `audit_type`      | string  | —            | Exact match on the audit record type (e.g. `SYSCALL`, `BPF`, `PROCTITLE`) |
| `q`               | string  | —            | Free-text search over the raw audit line                  |

**Response:**

```json
{
  "total": 108,
  "items": [
    {
      "id": "Y4tHP6ABQzU7nwqBcpRJ",
      "timestamp": "2026-08-26T18:38:48.706109+00:00",
      "log_timestamp": "2026-07-13T22:50:14.018Z",
      "model": "IsolationForest-v1",
      "prediction": -1,
      "risk_score": 54,
      "confidence": null,
      "hostname": "LinuxEndpoint",
      "audit_type": "SYSCALL",
      "message": "type=SYSCALL msg=audit(...): ...",
      "log": { "...full original filebeat/auditd document, verbatim..." }
    }
  ]
}
```

- `prediction`: `1` = normal, `-1` = anomaly (raw IsolationForest output).
- `risk_score`: `0`-`100`, higher = more anomalous.
- `confidence`: always `null` today — not implemented upstream in ml-service yet.
- `log`: the complete original source document as ml-service received it (varies in
  shape — see the two ingestion formats noted in `CLAUDE.md`), plus a `parsed` object.
- `hostname`, `audit_type`, `message` are convenience fields flattened out of `log`
  for table display; they're omitted if not present in the source document.

Example — top 5 anomalies:

```
curl "http://localhost:8080/api/logs?anomaly=true&sort_by=risk_score&order=desc&size=5"
```

### `GET /api/logs/{id}`

Fetch a single log entry by its Elasticsearch document ID (the `id` field from a list
response). Same shape as one item above. `404` if not found.

### `GET /api/stats`

Summary for an at-a-glance dashboard view.

```json
{
  "total": 5000,
  "anomaly_count": 108,
  "avg_risk_score": 37.92,
  "max_risk_score": 54
}
```

## Errors

Non-2xx responses are `{"error": "message"}`.

- `400` — invalid query parameter (bad type, out-of-range value, unknown enum value).
- `404` — `/api/logs/{id}` with no matching document.
- `502` — Elasticsearch query failed (connection issue, cluster error).

## Known limitations (first pass)

- CORS is wide open (`Access-Control-Allow-Origin: *`) to unblock local frontend
  development. Tighten before this is exposed anywhere beyond localhost.
- No auth on the API itself, matching the current (temporary) no-auth Elasticsearch
  setup — see `CLAUDE.md`.
- Pagination uses Elasticsearch `from`/`size`, which Elasticsearch limits to the top
  10,000 results by default (`index.max_result_window`). Fine at current data volumes;
  switch to `search_after` if deep pagination is ever needed.
