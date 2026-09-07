# Panoptic — project notes

Working notes for the pipeline: Filebeat → Elasticsearch → ml-service (enrichment) →
Elasticsearch → Go API → React frontend.

## Elasticsearch

- Reachable at `192.168.10.100:9200` (the host machine's LAN IP on `ens33`) — this is
  intentionally hardcoded in `ml-service/elastic.py` for now. Security is disabled
  (`xpack.security.enabled=false` in `docker-compose.yml`); `elastic.py` still passes
  `basic_auth=("elastic", "changeme")`, which the server currently ignores. Auth/TLS is
  planned for later — don't "fix" this mismatch without checking with the project owner.
- Raw logs live in the `filebeat-*` index pattern (currently the data stream
  `filebeat-9.4.3`, ~320k docs of Linux auditd data, spanning 2026-06-28 to 2026-07-31).
  **Two different shapes coexist** in this index depending on how Filebeat ingested them:
  - `filestream` input (minority, ~53k docs): raw audit line sits in `message`.
  - `auditd` module (majority, ~268k docs): `message` is **absent**; the raw audit line
    is instead in `event.original`, plus structured fields under `auditd.*`.
  - Anything that reads `log["message"]` directly will `KeyError` on the majority of
    real data. Use `parser.extract_raw_audit_text(log)`, which checks `message` first
    and falls back to `event.original`.
- ML-enhanced predictions are written to `panoptic-predictions` (separate index, not
  merged back into the source `filebeat-*` docs).

### `panoptic-predictions` document schema (derived from real data, 2026-08-26)

```json
{
  "@timestamp": "2026-08-26T17:52:11.585779+00:00",   // when the prediction was made (ISO 8601, UTC)
  "model": "IsolationForest-v1",                       // string, model identifier
  "prediction": 1,                                     // int: IsolationForest output (1 = normal, -1 = anomaly)
  "risk_score": 35.0,                                  // float, 0-100 (higher = more anomalous)
  "confidence": null,                                  // currently always null — not implemented
  "log": { /* the full original filebeat/auditd source document, verbatim, plus a `parsed` key */ }
}
```

`log.parsed` is added by `ml-service` before scoring: it's the audit line's `key=value`
pairs split into a flat dict (e.g. `{"type": "BPF", "op": "UNLOAD", ...}`). Field
presence varies a lot by audit record type (`type=` value) — don't assume any key
other than `type` is always present.

Note: `prediction` and `risk_score` are sometimes still floats-as-ints or similar minor
type variance depending on model/sklearn version; treat both as numeric, not strictly
int vs float.

## ml-service — issues found and fixed (2026-08-26)

The service was crash-looping (`docker logs ml-service` showed a Python traceback and
exit code 1) and had never written a correctly-shaped document. Fixes, in the order
that mattered:

1. **Root cause of the crash**: `requirements.txt` didn't pin the `elasticsearch`
   package version. It resolved to v9.5.0, which by default sends
   `Accept: application/vnd.elasticsearch+json; compatible-with=9` — the ES 8.18.0
   server rejects that outright (`BadRequestError: ... Accept version must be either
   version 8 or 7, but found 9`). Fixed by pinning `elasticsearch>=8.18.0,<9.0.0`.
2. **`main.py` crashed before even reaching Elasticsearch**: `time.sleep(300)` was
   called without `import time`. Added the import.
3. **Tuple/dict mismatch** (found and fixed earlier in the session, confirmed here by
   10 pre-existing garbage docs in `panoptic-predictions` with literal string values
   `"prediction": "prediction"` / `"risk_score": "risk_score"`): `main.py` did
   `prediction, score = predictor.predict(log)`, but `predict()` returns a dict —
   unpacking a dict as a tuple iterates its *keys*, not values. Fixed to read
   `result["prediction"]` / `result["risk_score"]`. The 10 garbage docs (plus 10 more
   generated during this session's testing) were deleted from `panoptic-predictions`
   after confirming with the project owner — nothing in `filebeat-*` was touched.
4. **It only ever re-scored the same 10 logs, forever**: `get_latest_logs()` always
   fetched the newest 10 docs by `@timestamp desc`. Since `filebeat-*` is a static
   historical dataset (not being live-appended), "latest 10" never changes — the
   service would loop on the same 10 documents every 5 minutes indefinitely and never
   touch the other ~99.99% of the backlog. Replaced with
   `get_unprocessed_logs(size)` in `elastic.py`, which derives a cursor from the max
   `log.@timestamp` already present in `panoptic-predictions` and fetches
   `filebeat-*` docs strictly newer than that, sorted ascending (tie-broken by
   `_seq_no`). This only works correctly given enough time between cycles for
   Elasticsearch's near-real-time refresh (~1s) to make newly-indexed docs visible —
   true for the real 300s loop, not for a tight loop with no delay.
5. **`KeyError: 'message'` on ~84% of real logs**: see the `auditd` module vs
   `filestream` shape difference above. Fixed via `parser.extract_raw_audit_text()`,
   used in both `predict.py` and `train.py`.
6. **Backlog throughput**: default batch size of 10 logs / 5 min would take >100 days
   to process the ~320k backlog. Bumped to `size=1000` in `main.py`'s call to
   `get_unprocessed_logs()` — at measured throughput this clears the backlog in
   roughly a day, then settles into steady-state processing of new arrivals.
7. **`prediction`/`risk_score` mapped as `text`, not numeric** (found while building
   the Go API, Phase 2): Elasticsearch infers a field's type from the *first* document
   it ever sees for that field name, and that mapping is permanent for the life of the
   index. The very first docs written into `panoptic-predictions` (back when the
   tuple-unpacking bug was live) had literal string values `"prediction"` /
   `"risk_score"`, so both fields got locked in as `text`. Every later numeric value
   was still being silently coerced to text — sorting by risk score would have sorted
   lexicographically (`"9.0"` > `"100.0"`) and numeric range filters wouldn't have
   worked at all. Fixed by deleting `panoptic-predictions` and recreating it with an
   explicit mapping (`prediction`: integer, `risk_score`: float, `confidence`: float,
   `log.@timestamp`: date, rest of `log` left dynamic). ml-service regenerated the
   ~1,100 lost docs within a couple of cycles — confirmed after the fix that
   `sort=risk_score:desc` returns correctly ordered results.

Not fixed / known non-blocking issues:
- `model.pkl` was trained under scikit-learn 1.4.1.post1; the container runs 1.9.0.
  This only produces an `InconsistentVersionWarning` on load, not a failure — but the
  model should be retrained (`train.py`) under the current sklearn version at some
  point to avoid relying on cross-version unpickling.
- `parse_message()` splits on whitespace only; audit lines containing the `\x1d`
  (unit separator) control character between fields without surrounding whitespace
  will glue two key=value pairs together (e.g. `res=1` and `AUID="unset"` become one
  garbled value). Pre-existing behavior, not changed in this pass.

## Go API (`api/`) — Phase 2, 2026-08-26

Built from scratch against the real schema above (the old `api/elastic/client.go` was
just a broken placeholder — a `main()` with a syntax error and a discarded client).
Full contract, query params, and response shapes are documented in `api/README.md`;
summary:

- `GET /health`, `GET /api/logs` (paginated/filterable/sortable), `GET /api/logs/{id}`,
  `GET /api/stats`. Verified against live Elasticsearch (both `go run .` and the
  Docker image) — real filtering, numeric sort by `risk_score`, get-by-id, 404/400
  handling all confirmed working.
- Uses the plain (untyped) `elasticsearch.NewClient`, not `NewTypedClient` — raw
  `map[string]interface{}` query bodies decoded into a small hand-rolled response
  struct (`api/elastic/predictions.go`). Simpler than the typed query DSL builder for
  this scope; revisit if the query surface grows a lot.
- Same Elasticsearch host/credentials as `ml-service` by default
  (`192.168.10.100` / `elastic:changeme`), overridable via `PANOPTIC_ES_ADDR` /
  `PANOPTIC_ES_USER` / `PANOPTIC_ES_PASSWORD` env vars.
- CORS is wide open (`*`) for local frontend dev — tighten later, see
  `api/README.md`'s "Known limitations".

## React frontend (`frontend/`) — Phase 3, 2026-08-26

Vite + plain React SPA (not Next.js — no SSR/API-route need against an
already-separate Go API; see `frontend/README.md`). Full details there;
summary:

- Dashboard: stats bar (`GET /api/stats`) + a sortable (click column header),
  filterable (anomaly-only, min risk score, audit type, free-text search),
  paginated table of logs (`GET /api/logs`). Click a row to expand the full
  original log document.
- Risk score and anomaly status use the design system's reserved status
  colors (good/warning/serious/critical, bucketed at 40/60/80), always paired
  with an icon + text label, never color alone.
- Verified with a real headless-browser run (Playwright; no Claude-in-Chrome
  extension available in this environment) against the live Go API and
  Elasticsearch — screenshotted initial load, sort-by-risk-score, anomaly
  filter, min-score filter, audit-type filter, free-text search, and row
  expansion. Zero console/page errors; filtered/sorted results cross-checked
  against expected values (e.g. anomaly filter showed exactly 108 of 108,
  matching `/api/stats`'s `anomaly_count`).
- `Dockerfile` added (nginx serving the Vite build). **Important**: Vite bakes
  `VITE_API_URL` in at build time, not runtime — set it via `--build-arg` per
  deployment target, it can't be changed with `docker run -e`.
- Environment note: this sandbox had no `node`/`npm` on `PATH`. A portable
  Node v22.14.0 was installed to `~/.local/node` and symlinked into
  `~/.local/bin` (already on `PATH`) rather than relying on `~/.bashrc`
  sourcing, which only happens in interactive shells.

## Phase 4 — ML / risk / MITRE rework, 2026-09-07

Large rework of the detection pipeline. The v1 service scored every audit
record (including PATH/CWD/PROCTITLE children) with a 10-feature vector
re-parsed from `event.original` text, and mapped `int((1 - decision_function)
* 50)` straight to a risk score — result: **82% of ~63k predictions scored
exactly 35.0**, whole range 35–54.

New layout under `ml-service/panoptic/` (each stage its own testable module):
`context` (raw doc → shape-agnostic `EventContext`, prefers ECS structured
fields), `enrich` (in-batch SYSCALL↔child correlation), `features` (~28-feature
registry), `profile` (frequency-baseline rarity), `signals` (batch-local
rolling auth-fail / port counters), `model` (StandardScaler + IsolationForest +
**percentile calibration** of `decision_function`), `mitre` (rule table, real
technique IDs only, `[]` when nothing ≥0.35), `risk` (composite CVSS-*inspired*
`security_risk_score`, weights in `artifacts/risk_weights.json`), `explain`
(template, no LLM), `alerts` (new `panoptic-alerts` index + explicit mapping),
`detector` (orchestrator, batches model scoring), `scenarios` (labelled
synthetic telemetry).

New output index **`panoptic-alerts`** (not `panoptic-predictions`) — richer
`detection{}` / `risk{}` / `mitre[]` / `explanation{}` schema, `log` kept
verbatim. Scan cursor moved to `panoptic-state/_doc/scan-cursor` (the old
"max @timestamp in the predictions index" trick breaks when only some events
produce alerts).

Config is all env-driven (`config.py`). Training is an explicit CLI
(`train.py`, random sample via `random_score`, not "latest N"); `evaluate.py`
and `report.py` are the eval + distribution tools.

Bugs found and fixed during this pass:
1. **auditd sequence number is not globally unique** — it cycles constantly, so
   in-batch enrichment merged unrelated events. Event id is now
   `epoch:sequence` from `msg=audit(EPOCH:SEQ)`.
2. **`auid` / `uid` unset sentinel** — auditd writes it as `4294967295`
   (unsigned −1). Wasn't normalised, so every boot-time root process read as a
   privilege *transition* and got flagged. Now mapped to unknown.
3. **`^@` in command lines** — Filebeat's auditd module renders the NUL arg
   separator as the literal two-char string `^@`, not a `\x00` byte, so the
   control-char stripper missed it. Added caret-notation handling.
4. **substring path matching** — `"/lib/systemd/system" in
   "/usr/lib/systemd/system-generators/..."` is true; the T1543.002 rule fired
   on every systemd generator. Rules now require a write-shaped syscall + a
   trailing-slash / `.service` path match.
5. **confidence always ~0** — used `offset_` (fixed at −0.5 for
   contamination=`auto`) as the boundary; the real boundary is
   `decision_function == 0`.
6. **`[model.score(x) for x in X]` in train.py** — 22k individual
   `decision_function` calls, ~15 min. Batched via `score_many`.

`scikit-learn` is now **pinned** (`==1.9.0`) so `model.pkl` always loads under
the version that wrote it. Trained artifacts are `.gitignored`; `train.py` /
`scripts/bootstrap.sh` regenerate them into the `ml_artifacts` volume.

Go API: `api/elastic/predictions.go` replaced by `alerts.go` + `queries.go` +
`legacy.go`. New endpoints `/api/alerts`, `/api/alerts/{id}`,
`/api/alerts/stats`, `/api/anomalies/timeline`, `/api/risk/distribution`,
`/api/mitre/techniques`. `/api/logs*` + `/api/stats` kept as a compat shim over
`panoptic-alerts`. Client takes an injectable `http.RoundTripper` for tests
(`go test ./...` runs with no cluster).

Frontend: `LogsTable`/`StatsBar` replaced by an Alert Center table + slide-over
`AlertDetail`, plus four Recharts panels (anomaly trend, risk distribution,
severity donut, ATT&CK coverage). `severity.js` holds the shared vocab. Vitest
+ RTL tests added (`npm test`); note `esbuild.jsx: 'automatic'` in
`vite.config.js` works around Vitest 2.x bundling an older Vite that can't load
`@vitejs/plugin-react` 6. Verified end-to-end with a Playwright run (zero
console errors; severity filter, min-risk filter, sort, detail drawer all
confirmed against live data).

`docker-compose.yml` now builds+runs ml-service / api / frontend too (not just
ES + Kibana). `./scripts/bootstrap.sh` is the one-command bring-up (waits for
ES health, builds, trains if no model, starts everything). ES address for
ml-service is now `PANOPTIC_ES_ADDR` (default unchanged at
`http://192.168.10.100:9200`; compose overrides to `http://elasticsearch:9200`).

The old `panoptic-predictions` index is superseded but not deleted — nothing
writes to it any more.
