# SentinelC Fleet Console

A zero-dependency web app (Node.js built-in modules only) that ingests
`sentinelc.exe --full --json` scan results from many Windows endpoints and shows
a fleet-wide threat dashboard. This is the product's management view.

No `npm install`: it runs with just `node server.js` (Node v24+).

## Quick start

### 1. Start the console

```sh
cd sentinelc/fleet-console
node server.js
```

On first start it prints the dashboard URL, console token, and host-token count:

```text
  SentinelC Fleet Console
  -----------------------
  URL:            http://127.0.0.1:8787/
  Console token:  3f9a...   (source: generated)
  Host tokens:    0 configured
  Data:           ...\fleet-console\data
```

The console token protects dashboard read APIs and is resolved in this order:

1. `SENTINELC_FLEET_TOKEN` environment variable.
2. `fleet-console/config.json` `{ "token": "..." }`.
3. Otherwise a new token is generated, printed, and written to `config.json`.

Each endpoint also needs its own host token for `/api/ingest`. Configure host
tokens in either `fleet-console/config.json`:

```json
{
  "token": "<dashboard-console-token>",
  "hostTokens": {
    "HOST1": "<long-random-host-token>",
    "HOST2": "<different-long-random-host-token>"
  }
}
```

or with `SENTINELC_FLEET_HOST_TOKENS`, either as JSON or
`HOST1=token1,HOST2=token2`.

### 2. Submit scans from each endpoint

On each Windows endpoint, run the agent script (it runs the scanner and uploads):

```powershell
$env:SENTINELC_FLEET_TOKEN = "<this endpoint's host token>"
.\submit.ps1 -ConsoleUrl https://<console-host>
```

For remote consoles, `submit.ps1` requires HTTPS. Plain HTTP is allowed only for
loopback URLs such as `http://127.0.0.1:8787`.

`submit.ps1`:

- runs `..\build\sentinelc.exe --full --json` and captures stdout,
- builds `{ hostname: $env:COMPUTERNAME, scannedAt: <now ISO>, scan: <parsed JSON> }`,
- `POST`s it to `/api/ingest` with `Authorization: Bearer <host-token>`,
- prints the result.

Schedule it (for example Task Scheduler, hourly) for continuous fleet coverage.

### 3. Open the dashboard

Browse to `http://127.0.0.1:8787/` and enter the console token. The fleet table
shows each host with colored CRIT / HIGH / MED / LOW badges, total, and
last-seen time. Click a host to see its full findings (rule, severity, target,
evidence). The view auto-refreshes every 15 seconds and the column headers are
click-to-sort.

## API

| Method | Path              | Auth           | Description |
|--------|-------------------|----------------|-------------|
| POST   | `/api/ingest`     | Host Bearer    | Ingest a scan: body `{ hostname, scannedAt?, scan }`. Token must match the submitted hostname. Returns `{ ok: true }`. |
| GET    | `/api/hosts`      | Console Bearer | Array of `{ hostname, lastSeen, counts, topRules }`, sorted by critical desc then high desc. |
| GET    | `/api/host/:name` | Console Bearer | One host's latest full `findings` plus its count `history`. |
| GET    | `/`               | none           | The dashboard HTML. |

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
  "findings": [ "... latest full findings ..." ],
  "history": [ { "timestamp": "...", "counts": { "total": 2 } } ]
}
```

Hostnames are sanitized to `[A-Za-z0-9._-]`; anything else, including path
traversal, is rejected with 400.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `PORT` | `8787` | Listen port. |
| `HOST` | `127.0.0.1` | Bind address. |
| `SENTINELC_FLEET_TOKEN` | see above | Console/read API bearer token. |
| `SENTINELC_FLEET_HOST_TOKENS` | none | Per-host ingest tokens as JSON or `HOST=token,HOST2=token2`. |

Request bodies are capped at 8 MB; malformed JSON returns 400; missing/wrong
tokens return 401. Ingest for a hostname without a configured host token returns
403.

## Security - read before deploying beyond localhost

Honest limitations:

- It binds to `127.0.0.1` by default. Exposing it on a LAN/WAN by changing
  `HOST` without a reverse proxy still serves the dashboard over plaintext HTTP.
  Use TLS for anything beyond localhost.
- Endpoint ingest uses per-host bearer tokens. Protect `config.json`; a stolen
  host token can submit for that one hostname.
- `GET /api/hosts` and `GET /api/host/:name` require the console bearer token.
  Keep the port on localhost or behind a TLS reverse proxy with access control.

For a real multi-machine deployment, terminate TLS at a reverse proxy or front
the console with an authenticated tunnel. The helper upload scripts reject
non-loopback HTTP URLs to avoid sending scan telemetry and bearer tokens over
the network in plaintext.

The token lives in `config.json` and scan data lives in `data/`; both are
gitignored and must not be committed.
