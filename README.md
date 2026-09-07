# Panoptic

A behavioural-detection SIEM pipeline for Linux endpoint telemetry, built as a
learning project. auditd logs are shipped by Filebeat into Elasticsearch, scored
by a Python ML service (Isolation Forest + a composite risk engine + rule-based
MITRE ATT&CK tagging), and served through a Go REST API to a React security
dashboard.

```
                 Linux (auditd) / [Windows Sysmon]
                              │
                          Filebeat
                              │
                              ▼
                        Elasticsearch  (filebeat-*  — raw telemetry)
                              │
                              ▼
                    ┌──────  Python ML service  ──────┐
                    │                                 │
              feature engineering              behavioural profile
              (ECS-structured first)          (frequency baselines)
                    │                                 │
                    ▼                                 ▼
          Isolation Forest  ──► anomaly score (percentile-calibrated)
                    │
         ┌──────────┼──────────────┐
         ▼          ▼              ▼
   MITRE ATT&CK   composite     explanation
   rule mapping   risk engine   generator
         └──────────┼──────────────┘
                    ▼
              Elasticsearch  (panoptic-alerts — scored alerts)
                    │
                    ▼
                Go REST API   /api/alerts · /api/anomalies/timeline
                    │         /api/risk/distribution · /api/mitre/techniques
                    ▼
             React dashboard   Alert Center · Anomaly Trend · Risk & Severity
                               distribution · ATT&CK coverage · Alert detail
```

> Windows/Sysmon is drawn in the diagram because the design supports it, but the
> shipped dataset and detectors are Linux auditd only.

## Components

| Component | Stack | What it does |
|---|---|---|
| [`ml-service/`](ml-service/README.md) | Python, scikit-learn | Reads `filebeat-*`, extracts security features, scores each event with Isolation Forest, computes a 0–100 `security_risk_score`, maps MITRE ATT&CK techniques, writes `panoptic-alerts`. |
| [`api/`](api/README.md) | Go | REST API over `panoptic-alerts` — filterable/sortable alert list, single alert, stats, anomaly timeline, risk distribution, ATT&CK technique counts. Keeps the pre-2.0 `/api/logs` surface as a compatibility shim. |
| [`frontend/`](frontend/README.md) | React + Vite + Recharts | SOC-style dashboard: stat cards, anomaly trend, risk/severity distributions, ATT&CK coverage, filterable alert table, full alert-detail drawer. |

Each subdirectory has its own README with detail. `docker-compose.yml` builds and
runs everything.

## Quick start

Panoptic scores data that already exists in Elasticsearch under `filebeat-*`;
this repo does **not** ship the endpoint→Filebeat→Elasticsearch ingest pipeline.
With that data present:

```bash
./scripts/bootstrap.sh            # ES+Kibana up, build images, train model, start all services
# first-run backlog is large? clear it faster:
FAST_BACKFILL=1 ./scripts/bootstrap.sh
```

Then:

| | URL |
|---|---|
| Dashboard | http://localhost:8081 |
| API | http://localhost:8080/api/alerts |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |

Manual equivalent:

```bash
docker compose up -d elasticsearch kibana
docker compose build
docker compose run --rm ml-service python train.py     # writes model into the ml_artifacts volume
docker compose up -d
docker compose logs -f ml-service                       # watch the backlog drain
```

`ml-service` won't start scoring until a model exists in the `ml_artifacts`
volume — it logs a reminder and retries every 30s until `train.py` has run.

## ML pipeline

Per event, in order (each stage is an independently testable module under
`ml-service/panoptic/`):

1. **`context`** — normalise the raw ES document into an `EventContext`.
   Filebeat delivers auditd two ways (a raw `filestream` tail and the `auditd`
   module); this layer papers over the difference and prefers the structured ECS
   fields (`process.*`, `user.*`, `event.*`, `auditd.log.*`) over re-parsing text.
2. **`enrich`** — in-batch correlation: an auditd event is several records
   sharing `msg=audit(epoch:seq)` (SYSCALL + EXECVE + PROCTITLE + CWD + PATH +
   SOCKADDR). The child records enrich the parent SYSCALL; only standalone
   records are scored (PATH/CWD/PROCTITLE/EXECVE/SOCKADDR are consumed but not
   scored on their own).
3. **`features`** — ~28 numeric features (see below).
4. **`profile`** — behavioural baseline: smoothed frequency tables
   (`exe` per host, `exe` per user, record-type, …) → a 0–1 rarity estimate.
5. **`model`** — Isolation Forest → percentile-calibrated anomaly score.
6. **`mitre`** — rule-based ATT&CK technique tags.
7. **`risk`** — composite CVSS-inspired `security_risk_score` (0–100) + severity.
8. **`explain`** — template-generated title + summary + factor list.
9. **`alerts`** — assemble the `panoptic-alerts` document.

### Feature engineering

Structured, modular (`panoptic/features.py` — each feature a pure function of
`EventContext`, registered in a fixed order that *is* the model input contract).
Grouped by why they help unsupervised anomaly detection:

| Group | Features | Rationale |
|---|---|---|
| Temporal | `hour`, `is_offhours`, `is_weekend` | interactive intrusion skews to nights/weekends; workstation auditd volume is mostly business-hours automation |
| Privilege | `is_root`, `privilege_transition`, `is_privileged_key` | root actions and login→root transitions (sudo/su) are where compromise does damage; the audit `key=` tag marks rule-flagged sensitive syscalls |
| Process shape | `exe_depth`, `exe_unusual_dir`, `is_shell`, `is_interpreter`, `is_network_tool`, `is_scanner`, `proctitle_len`, `proctitle_tokens`, `arg_count` | execution from `/tmp`, long/obfuscated command lines, unexpected shells/interpreters/net-tools are classic execution & C2 signals |
| Authentication | `auth_failure`, `recent_auth_failures` | one failure is noise; a burst is brute force / spraying |
| Network | `is_remote`, `dest_port_class`, `recent_distinct_ports` | remotely-originated activity and port fan-out (scanning) matter |
| Behavioural rarity | `host_exe_rarity`, `user_exe_rarity`, `exe_rarity`, `record_type_rarity`, `user_host_rarity` | "have we ever seen *this user* run *this binary* on *this host*?" — the biggest fix for the old collapsed-score problem, where the vector was near-constant for ~80% of records |

`recent_auth_failures` / `recent_distinct_ports` are batch-local rolling
counters (`panoptic/signals.py`) — the window resets at batch boundaries, which
is acceptable and documented.

### Isolation Forest

Kept as the detector: fast, unsupervised, handles mixed binary/continuous
features, and explainable (path length in random trees). The task — flag events
unlike the learned baseline — is exactly what it is for. A deep model would add
opacity and a training-data appetite we don't have for ~28 tabular features.

Configuration is explicit and env-driven (`ml-service/config.py`), with defaults
tuned for this dataset:

| Env | Default | Note |
|---|---|---|
| `PANOPTIC_IF_N_ESTIMATORS` | 300 | more trees than sklearn's 100 |
| `PANOPTIC_IF_MAX_SAMPLES` | 4096 | **much** larger than sklearn's 256 — a wide "normal" manifold is badly under-described by 256 samples, a major contributor to every event scoring ~35 in v1 |
| `PANOPTIC_IF_CONTAMINATION` | `auto` | only affects the binary `predict()` label, not the continuous score used for risk |
| `PANOPTIC_IF_RANDOM_STATE` | 42 | reproducible |
| `PANOPTIC_TRAIN_SAMPLE_SIZE` | 40000 | random sample of `filebeat-*` (via `random_score`), not "latest N" |

Pipeline = `StandardScaler` → `IsolationForest` (scaling makes split thresholds
comparable across uid-sized integers and 0/1 flags).

### Risk scoring — why scores are now diverse

v1 mapped `anomaly_score → risk_score` with `int((1 - decision_function) * 50)`.
Isolation Forest's `decision_function` for inliers clusters in a band a few
hundredths wide, and `int()` truncated it further, so **82 % of events scored
exactly 35** and the whole range was 35–54.

Fixes:

* **Percentile calibration.** Training `decision_function` scores are stored
  (`calibration.json`); at inference the raw score becomes its percentile in
  that distribution, so `anomaly_score` uses the whole 0–1 range.
* **Richer features** (rarity especially) so the model has real variance to
  split on.
* **The risk score is composite**, not a rescaled model output:

```
impact          = w·(privilege, confidentiality, integrity, availability)      # 0..1
exploitability  = w·(privilege_required, attack_complexity, auth_context, remote)  # 0..1
technical       = 0.6·impact + 0.4·exploitability          (impact-weighted, CVSS-style)
technical       = max(technical, 0.35 + 0.6·technique_severity)   # a confident ATT&CK
                                                                 # match is a strong prior
context_mod     = clamp(0.45 + 0.35·anomaly + 0.15·rarity + 0.15·technique_severity
                        + 0.20·(asset_criticality−0.5)·2,  0.25, 1.30)
security_risk_score = clamp(round(100 · technical · context_mod), 0, 100)
```

Every sub-factor is a documented 0–1 estimate derived from real event features
(`panoptic/risk.py`). Weights live in `artifacts/risk_weights.json` (env/file
override, not hardcoded). Two events differing in privilege, target sensitivity,
anomaly, rarity, or technique get materially different scores.

**Severity bands** (`PANOPTIC_SEV_*` to adjust): `0–19` informational ·
`20–39` low · `40–59` medium · `60–79` high · `80–100` critical.

On real workstation telemetry most events genuinely *are* routine, so the risk
distribution is weighted toward low — that is correct SIEM behaviour, not score
collapse. The `anomaly_score` (fully spread 0–1) and the clear
normal-vs-simulated-attack separation (see evaluation) are the diversity signal.

### CVSS-inspired, not CVSS

CVSS scores *vulnerability* severity. These are *behavioural detections*, so
Panoptic borrows the shape — Impact and Exploitability sub-scores combined into a
technical severity, then adjusted by contextual/environmental factors — but not
the formula or the vector strings. The field is named `security_risk_score`;
nothing here is or claims to be an official CVSS value.

| CVSS-like dimension | How Panoptic estimates it |
|---|---|
| Privilege / Confidentiality / Integrity / Availability impact | root vs privilege-transition vs unprivileged; access to `/etc/shadow`, SSH keys, `.bash_history`; writes to persistence paths, account/config changes; service-stop / audit-disable commands |
| Privilege required | lower for actions a normal user can do → more exploitable |
| Attack complexity | interactive shell / single command → low complexity |
| Authentication context | recent failed-auth burst, remote login |
| Remote | SOCKADDR to an external IP, ssh/scp, remote `addr=` |
| Environmental | per-host `asset_criticality` (0–1, default 0.5, `PANOPTIC_ASSET_CRITICALITY` JSON) |
| Anomaly / rarity / technique | model anomaly percentile, profile rarity, mapped-technique base severity |

### MITRE ATT&CK mapping

Deliberately a hand-written rule table (`panoptic/mitre.py`), not an NLP model:
every tag has a named, readable condition; technique IDs are real Enterprise
ATT&CK; when nothing matches with confidence ≥ 0.35 the alert gets `mitre: []`
rather than a guess. Multiple techniques per alert are supported (array,
highest-confidence first). Covered techniques include T1059.004/.006 (shells /
Python), T1105 (ingress tool transfer), T1046 (network scanning), T1021.004
(SSH), T1110 (brute force — needs the rolling failure count), T1548.003 (sudo to
a shell), T1003.008 (`/etc/shadow` access), T1053.003 (cron), T1543.002 (systemd
unit writes), T1562.001 (disable auditd / SELinux), T1070.002/.003 (log / history
clearing), T1136.001 / T1098 (account creation / manipulation).

### Alert explanations

Template-generated from the same features/context the score is built from
(`panoptic/explain.py`) — no LLM, so an explanation can never assert something
the detection logic didn't find. Each alert carries `explanation.title`,
`explanation.summary` (concrete: process, user, host, escalation origin, rarity,
auth-failure count, remote origin, sensitive files), and `explanation.factors`
(label/value pairs for the UI), plus a machine-readable `risk.factors` list.

## Alert schema (`panoptic-alerts`)

Numeric/keyword/date fields the API filters/sorts/aggregates on are mapped
explicitly (`panoptic/alerts.py`); the original document is kept verbatim under
`log` (dynamic, `ignore_dynamic_beyond_limit` so a wide auditd record can't
reject the doc).

```jsonc
{
  "@timestamp": "…",                       // when scored
  "event":  { "id", "timestamp", "type", "action", "category", "module", "outcome" },
  "host":   { "name", "ip", "criticality" },
  "user":   { "id", "name", "audit_id", "audit_name", "is_root", "privilege_transition" },
  "process":{ "name", "executable", "command_line", "args", "pid", "parent_pid",
              "working_directory", "audit_key" },
  "network":{ "direction", "destination_ip", "destination_port", "source_ip" },  // when present
  "detection": {
    "model": "isolation_forest", "model_version": "2.0", "detection_version": "2.0",
    "anomaly_score": 0.94,        // 0..1, percentile-calibrated
    "raw_score": -0.08,           // raw decision_function
    "confidence": 0.88,
    "prediction": -1              // legacy IsolationForest label
  },
  "risk": {
    "score": 78, "severity": "high", "model": "panoptic-risk-v1",
    "impact": 0.72, "exploitability": 0.55,
    "technical_severity": 0.7, "context_modifier": 1.1,
    "factors": ["privilege_transition", "rare_behaviour", "sudo"],
    "components": { "anomaly": 0.94, "rarity": 0.8, "impact.privilege": 1.0, … }
  },
  "mitre": [
    { "tactic": "Privilege Escalation", "tactic_id": "TA0004",
      "technique_id": "T1548.003", "technique_name": "…", "confidence": 0.8 }
  ],
  "explanation": { "title": "…", "summary": "…", "factors": [ { "label", "value" } ] },
  "signals": { "recent_auth_failures": 0, "recent_distinct_ports": 0 },
  "log": { /* full original source document */ }
}
```

## Model evaluation

Unsupervised model, so labels are used only to *measure* it, never to train it.
`ml-service/panoptic/scenarios.py` generates labelled synthetic auditd telemetry:

* **normal** — developer activity, routine `sudo apt`, normal SSH login, cron, service restart
* **malicious** — SSH brute force, sudo→root shell, nmap scan, `curl|bash`, reverse shell, `/etc/shadow` read, disable auditd, cron persistence, add-user

`docker compose run --rm ml-service python evaluate.py` scores them and reports
precision / recall / F1 / false-positive rate, MITRE mapping accuracy, per-scenario
detection rate, and score distribution by label. Current numbers (model trained
on the real dataset, `severity ≥ high` = alert):

```
precision 1.00   recall 0.77   f1 0.87   false-positive rate 0.00
MITRE technique mapping 0.73
risk score:   normal median 29   malicious median 69
```

**Limitations, stated honestly:**

* "detected a *simulated* attack" is weaker evidence than "detected a real
  attack" — the synthetic events are shaped by the same assumptions as the
  detectors.
* The synthetic "normal" set is a tiny, clean slice of real host activity, so the
  measured false-positive rate is optimistic. Cross-check against live data with
  `report.py`.
* Synthetic events run on a host/user absent from the training baseline, so their
  *anomaly* scores are uniformly high; the class separation there comes from the
  composite risk engine (privilege / technique / rarity-vs-real-profile), which
  is by design.
* `recall < 1` is mostly the brute-force scenario: the first few failed logins
  correctly *don't* alert; only the burst does.

## Score distribution report

`docker compose run --rm ml-service python report.py` prints, against the live
`panoptic-alerts` index: risk-score bands and top values, severity counts,
anomaly-score histogram, and top ATT&CK techniques. `report.py --assert-spread
0.5` exits non-zero if any single risk-score value holds > 50 % of alerts — a
regression guard for the original "everything is 35" failure.

## Generating test telemetry

* **Synthetic, in-process** — `python evaluate.py` / the `scenarios` module (no
  cluster needed).
* **Real** — this repo assumes `filebeat-*` is already populated. To generate
  more, run auditd + Filebeat's auditd module on a Linux host pointed at this
  Elasticsearch. A minimal audit ruleset (`/etc/audit/rules.d/`) flagging
  `execve`, identity files, `privileged_commands`, and logins gives the richest
  signal.

## Testing

```bash
# ML
cd ml-service && pip install -r requirements-dev.txt && pytest        # ~58 tests

# API
cd api && go test ./...                                                # handlers + query layer, mocked ES

# Frontend
cd frontend && npm install && npm test                                # vitest + RTL, ~29 tests
```

`ml-service/tests/test_evaluation.py` is the CI-able detection gate (asserts
class separation and non-collapsed scores, not production-grade metrics).

## Configuration reference

| Env | Service | Default | Purpose |
|---|---|---|---|
| `PANOPTIC_ES_ADDR` | ml, api | `http://192.168.10.100:9200` (compose overrides to `http://elasticsearch:9200`) | Elasticsearch |
| `PANOPTIC_ES_USER` / `_PASSWORD` | ml, api | `elastic` / `changeme` | ignored server-side today (security disabled) |
| `PANOPTIC_ALERTS_INDEX` | ml, api | `panoptic-alerts` | alert index |
| `PANOPTIC_BATCH_SIZE` | ml | `1000` | source docs consumed per cycle |
| `PANOPTIC_LOOP_INTERVAL` | ml | `300` | seconds between cycles |
| `PANOPTIC_IF_*` | ml (train) | see above | Isolation Forest params |
| `PANOPTIC_TRAIN_SAMPLE_SIZE` / `_SEED` | ml (train) | `40000` / `1337` | training sample |
| `PANOPTIC_SEV_LOW/MEDIUM/HIGH/CRITICAL` | ml | `20/40/60/80` | severity band lower bounds |
| `PANOPTIC_ANOMALY_LABEL_PCT` | ml | `0.98` | calibrated-score percentile at/above which `prediction` = −1 (replaces IsolationForest's noisy `contamination=auto` label) |
| `PANOPTIC_ASSET_CRITICALITY` | ml | `{}` | per-host criticality JSON |
| `PORT` | api | `8080` | HTTP port |
| `PANOPTIC_CORS_ORIGINS` | api | `*` | comma list; tighten before exposing |
| `VITE_API_URL` | frontend (build arg) | `http://localhost:8080` | baked at build time — the URL the *browser* uses |

## Limitations & future work

* **No auth/TLS** anywhere — Elasticsearch security is disabled, the API is
  open, CORS is `*`. Fine for a local lab; must change before any real exposure.
* **Historical dataset.** The shipped `filebeat-*` data is from mid-2026; the
  dashboard's default time range is "all time" for that reason.
* **Linux auditd only.** The context/feature layer is structured so Sysmon could
  be added, but there are no Windows detectors yet.
* **Rolling signals reset per batch** — brute-force / scan detection can miss a
  burst that straddles a batch boundary.
* **MITRE mapping is heuristic** and rule-based; it will miss techniques it has
  no rule for and can over-tag broad ones (tuned conservatively, but not perfect).
* **`confidence`** is a heuristic margin-to-boundary sigmoid, not a calibrated
  probability.
* Model retraining is manual by design (reproducible, no drift/poisoning risk);
  there is no automatic retrain loop.
* Cross-version model pickles: `requirements.txt` pins `scikit-learn` so the
  stored `model.pkl` always loads under the version that wrote it.

## Development note

Portions of this project (debugging, the Go API, the React frontend, and the
2.0 ML/risk/ATT&CK rework) were built with an agentic coding assistant (Claude
Code). Design decisions, review, and verification were done by the project owner.
