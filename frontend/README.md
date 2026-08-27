# Panoptic frontend

A minimal dashboard over the Panoptic Go API: a filterable/sortable table of
ML-enhanced logs, with an at-a-glance stats bar. Built with Vite + React (plain
client-side SPA, no Next.js) — see "Why Vite, not Next.js" below.

## Running

```
npm install
npm run dev
```

Opens on `http://localhost:5173`. By default it calls the API at
`http://localhost:8080` (see `src/api.js`); override with a `.env.local`:

```
VITE_API_URL=http://your-api-host:8080
```

### Docker

```
docker build -t panoptic-frontend --build-arg VITE_API_URL=http://192.168.10.100:8080 .
docker run -p 8081:80 panoptic-frontend
```

Vite bakes `VITE_*` env vars into the JS bundle at **build time**, not runtime —
the API URL must be known when the image is built, not passed via `docker run -e`.

## What it does

- Stats bar: total logs scored, anomalies flagged, avg/max risk score
  (`GET /api/stats`).
- Table of logs (`GET /api/logs`) — sortable by time or risk score (click a
  column header), filterable by anomaly-only, minimum risk score, audit type,
  and free-text search over the raw audit line. Paginated (20/page).
- Click a row to expand the full original log document (raw JSON) for
  drill-down.
- Risk score gets a color-coded bar (good/warning/serious/critical bucketed
  at 40/60/80) and every status indicator pairs an icon (dot) with a text
  label — never color alone.

## Why Vite, not Next.js

This is a client-side-only dashboard consuming an existing, separately-hosted
Go REST API — there's no server-rendering, SEO, or API-route need that Next.js
solves. Next.js would add a Node server process, routing conventions, and build
complexity with no corresponding benefit here. Vite gives a plain React SPA
with fast dev iteration and a static `dist/` output that any web server
(nginx, S3, etc.) can serve.

## Known limitations (first pass)

- No auto-refresh/polling — data updates on manual "Refresh" or when a filter
  changes. ml-service is still processing its backlog in the background;
  reload to see new predictions land.
- `confidence` is not surfaced in the UI — the API always returns `null` for
  it today (not implemented upstream in ml-service).
- No client-side routing/deep-linking to a specific log or filter state (no
  URL-synced query params) — everything lives in component state.
- Audit type filter is a free-text exact-match field, not a populated
  dropdown — there's no endpoint yet enumerating known audit types.
