# SentinelC Fleet Console

A zero-dependency web app (Node.js built-in modules only) that ingests
`sentinelc.exe --full --json` scan results from many Windows endpoints and shows
a fleet-wide threat dashboard. This is the product's management view.

No `npm install` — it runs with just `node server.js` (Node v24+).

## Quick start

### 1. Start the console

```sh
cd sentinelc/fleet-console
node server.js
```

On first start it prints the dashboard URL and an auth token, e.g.:

```
  SentinelC Fleet Console
  -----------------------
  URL:    http://127.0.0.1:8787/
  Token:  3f9a...   (source: generated)
  Data:   ...\fleet-console\data
```

The token is resolved in this order:

1. `SENTINELC_FLEET_TOKEN` environment variable.
2. `fleet-console/config.json` `{ "token": "..." }`.
3. Otherwise a new token is generated, printed, and written to `config.json`.

Copy the token — endpoints need it to submit.

### 2. Submit scans from each endpoint

On each Windows endpoint, run the agent script (it runs the scanner and uploads):

```powershell
$env:SENTINELC_FLEET_TOKEN = "<token from the console>"
.\submit.ps1 -ConsoleUrl http://<console-host>:8787
```

`submit.ps1`:

- runs `..\build\sentinelc.exe --full --json` and captures stdout,
- builds `{ hostname: $env:COMPUTERNAME, scannedAt: <now ISO>, scan: <parsed JSON> }`,
- `POST`s it to `/api/ingest` with `Authorization: Bearer <token>`,
- prints the result.

Schedule it (e.g. Task Scheduler, hourly) for continuous fleet coverage.

### 3. Open the dashboard

Browse to `http://127.0.0.1:8787/`. The fleet table shows each host with colored
CRIT / HIGH / MED / LOW badges, total, and last-seen time. Click a host to see
its full findings (rule, severity, target, evidence). The view auto-refreshes
every 15 seconds and the column headers are click-to-sort.

## API

| Method | Path              | Auth   | Description |
|--------|-------------------|--------|-------------|
| POST   | `/api/ingest`     | Bearer | Ingest a scan: body `{ hostname, scannedAt?, scan }`. Returns `{ ok: true }`. |
| GET    | `/api/hosts`      | none   | Array of `{ hostname, lastSeen, counts, topRules }`, sorted by critical desc then high desc. |
| GET    | `/api/host/:name` | none   | One host's latest full `findings` plus its count `history`. |
| GET    | `/`               | none   | The dashboard HTML. |

`scan` accepts either the modern object shape (`{ findings: [...] }`) or a bare
array of findings from older scanner output. Each finding may carry `rule`,
`severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO), `confidence`, `title`, `evidence`,
`target`, `pid`.

## Storage layout

One JSON file per host under `data/<safe-hostname>.json`:

```json
{
  "hostname": "TESTPC",
  "lastSeen": "2026-06-14T...Z",
  "counts": { "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 2 },
  "topRules": [ { "rule": "CRED.LSASS_HANDLE", "count": 1 } ],
  "findings": [ ... latest full findings ... ],
  "history": [ { "timestamp": "...", "counts": { ... } } ]   // last 20 scans
}
```

Hostnames are sanitized to `[A-Za-z0-9._-]`; anything else (including path
traversal) is rejected with 400.

## Configuration

| Env var                 | Default     | Meaning |
|-------------------------|-------------|---------|
| `PORT`                  | `8787`      | Listen port. |
| `HOST`                  | `127.0.0.1` | Bind address. |
| `SENTINELC_FLEET_TOKEN` | (see above) | Shared bearer token. |

Request bodies are capped at 8 MB; malformed JSON returns 400; missing/wrong
token returns 401.

## SECURITY — read before deploying beyond localhost

This is an MVP. Honest limitations:

- It binds to **127.0.0.1** by default. Exposing it on a LAN/WAN (changing
  `HOST`) sends scan data and the bearer token over **plaintext HTTP**.
- It uses a **single shared bearer token** for all endpoints. There is no
  per-endpoint identity, so any holder of the token can impersonate any host.
- `GET /api/hosts` and `GET /api/host/:name` are **unauthenticated** (they only
  serve already-ingested summaries to anyone who can reach the port). Keep the
  port on localhost / behind a reverse proxy.

For a real multi-machine deployment you need: **TLS** (terminate at a reverse
proxy or add HTTPS), **per-endpoint credentials** (mTLS or per-host tokens),
and authentication on the read endpoints. Those are out of MVP scope.

The token lives in `config.json` and scan data lives in `data/` — both are
**gitignored** and must not be committed.
