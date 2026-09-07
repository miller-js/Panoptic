# ml-service

Reads raw auditd events from `filebeat-*`, scores each security-relevant event,
and writes a `panoptic-alerts` document. Model training is a separate, explicit
step.

## Layout

```
main.py            scoring loop (the container's default command)
train.py           (re)train the model + calibration + behavioural profile  -> artifacts/
evaluate.py        score labelled synthetic telemetry, report metrics
report.py          distribution report over the live panoptic-alerts index
config.py          all env-driven configuration
elastic.py         the only module that talks to Elasticsearch
panoptic/
  context.py       raw ES doc            -> EventContext (shape-agnostic)
  parser.py        raw auditd text helpers
  enrich.py        in-batch SYSCALL<->child-record correlation
  features.py      EventContext          -> ~28-value feature vector (registry)
  profile.py       historical events     -> frequency baselines / rarity
  signals.py       batch-local rolling counters (auth failures, ports)
  model.py         Isolation Forest + percentile calibration
  mitre.py         rule-based ATT&CK technique mapping
  risk.py          composite CVSS-inspired security_risk_score
  explain.py       template explanation generator
  alerts.py        panoptic-alerts schema + document builder
  scenarios.py     labelled synthetic auditd telemetry (for evaluate.py)
tests/             pytest  (run: pip install -r requirements-dev.txt && pytest)
artifacts/         model.pkl, calibration.json, profile.json, risk_weights.json
                   (generated — .gitignored; risk_weights.json is written with
                    defaults on first train and can then be hand-tuned)
```

## Run

```bash
# scoring loop (default)
docker compose up -d ml-service

# train / retrain -> writes into the ml_artifacts volume
docker compose run --rm ml-service python train.py
docker compose run --rm ml-service python train.py --sample-size 80000 --contamination 0.03
docker compose run --rm ml-service python train.py --dry-run     # print score spread, don't save

# evaluate against simulated attacks
docker compose run --rm ml-service python evaluate.py --repeats 3 --json eval.json

# live score distribution (regression guard for the "everything is 35" bug)
docker compose run --rm ml-service python report.py --assert-spread 0.5
```

Without Docker: `pip install -r requirements.txt`, set `PANOPTIC_ES_ADDR`, run
the scripts directly. (`requirements-dev.txt` adds `pytest`.)

## Behaviour notes / gotchas

* **Model must exist before scoring.** `main.py` waits (logging a reminder every
  30s) until `artifacts/model.pkl` is present. `train.py` needs Elasticsearch
  reachable and ≥ ~500 scorable events in the sample.
* **`scikit-learn` is pinned.** A model pickled by one sklearn version can break
  when unpickled by another; the pin keeps `model.pkl` loadable.
* **Scored vs consumed.** PATH / CWD / PROCTITLE / EXECVE / SOCKADDR records are
  consumed (the scan cursor advances past them) and used to enrich their parent
  SYSCALL, but never produce their own alert.
* **Scan cursor** lives in `panoptic-state/_doc/scan-cursor` (max `@timestamp`
  consumed). Delete that doc to re-scan from the beginning; delete
  `panoptic-alerts` too for a clean rebuild.
* **auditd event id** is `epoch:sequence` from `msg=audit(…)` — the bare
  sequence number is not globally unique and cycles constantly across a large
  historical index.
* **Rolling signals reset at batch boundaries** — see `signals.py`.

See the repo README for the feature list, risk formula, ATT&CK coverage, and
evaluation methodology.
