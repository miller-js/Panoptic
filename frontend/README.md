# Panoptic frontend

A SOC-analyst dashboard over the Panoptic Go API. Vite + React (plain
client-side SPA) + Recharts.

## Running

```bash
npm install
npm run dev            # http://localhost:5173, expects the API at http://localhost:8080
```

Override the API URL with `.env.local`:

```
VITE_API_URL=http://your-api-host:8080
```

### Docker

```bash
docker build -t panoptic-frontend --build-arg VITE_API_URL=http://localhost:8080 .
docker run -p 8081:80 panoptic-frontend
# or: docker compose up -d frontend
```

`VITE_API_URL` is baked into the JS bundle at **build time** — it must be the
URL the *browser* uses to reach the API (so, the host-published port, not a
Docker network name). It cannot be changed with `docker run -e`.

## What it shows

* **Stat cards** — total alerts, critical / high counts, model anomalies, avg &
  max risk (`GET /api/alerts/stats`).
* **Event & anomaly trend** — events scored vs model anomalies vs high/critical
  alerts over time (`GET /api/anomalies/timeline`), range selector.
* **Risk score distribution** — alert count per 0–100 band; click a bar to
  filter (`GET /api/risk/distribution`).
* **Severity breakdown** — donut + legend; click to filter.
* **MITRE ATT&CK coverage** — ranked technique list; click a row to filter the
  table by that technique (`GET /api/mitre/techniques`).
* **Alert Center** — filterable/sortable table (`GET /api/alerts`). Filters:
  severity chips, anomalies-only, time range, min/max risk, host, user, event
  type, technique, free-text. Click a row for the **detail drawer**: why it
  fired, risk factors + sub-scores, ATT&CK techniques (linked to attack.mitre.org),
  event / host / user / process / network fields, detection metadata, and the
  raw original document.

Risk score and severity always pair a colour with a glyph + text label
(design-system status colours, never colour alone).

## Time range default

The shipped dataset is historical (mid-2026), so the default range is **All
time**. "Last 7/30 days" will show nothing against that data.

## Tests

```bash
npm test        # vitest + Testing Library (~29 tests)
```

Covers: severity/score helpers, the API client (query serialisation, error
paths), the alert table (render / empty / sort / select), the detail drawer, the
filter bar, chart empty/error states, and an `App` integration pass with a
mocked API (renders from data, surfaces API errors, severity + technique filters
drive requests, detail panel opens).

Vitest 2.x bundles an older Vite that can't load `@vitejs/plugin-react` 6, so
`vite.config.js` sets `esbuild.jsx: 'automatic'` for the test transform; the
production build still goes through the plugin.

## Why Vite, not Next.js

Client-side-only dashboard against an existing separate Go API — no SSR, SEO, or
API-route need. Vite gives a plain React SPA and a static `dist/` any web server
can serve.

## Known limitations

* No auto-refresh — use the Refresh button or change a filter.
* No URL-synced filter state / deep-linking.
* Recharts makes the bundle ~640 KB (176 KB gzipped); acceptable here, could be
  code-split later.
