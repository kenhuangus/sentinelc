'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const CONFIG_PATH = path.join(ROOT, 'config.json');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT, 10) || 8787;
const MAX_BODY = 8 * 1024 * 1024; // 8 MB
const HISTORY_LEN = 20;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// ---------------------------------------------------------------------------
// Token resolution: env > config.json > generate+persist
// ---------------------------------------------------------------------------
function resolveToken() {
  if (process.env.SENTINELC_FLEET_TOKEN && process.env.SENTINELC_FLEET_TOKEN.trim()) {
    return { token: process.env.SENTINELC_FLEET_TOKEN.trim(), source: 'env' };
  }
  try {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    if (cfg && typeof cfg.token === 'string' && cfg.token.trim()) {
      return { token: cfg.token.trim(), source: 'config.json' };
    }
  } catch (_) { /* missing/unreadable config -> generate */ }

  const token = crypto.randomBytes(24).toString('hex');
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify({ token }, null, 2) + '\n', { mode: 0o600 });
  } catch (e) {
    console.error('WARN: could not write config.json:', e.message);
  }
  return { token, source: 'generated' };
}

const { token: AUTH_TOKEN, source: TOKEN_SOURCE } = resolveToken();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function ensureDir(d) {
  try { fs.mkdirSync(d, { recursive: true }); } catch (_) {}
}
ensureDir(DATA_DIR);

function sanitizeHostname(name) {
  if (typeof name !== 'string') return null;
  const trimmed = name.trim();
  if (!trimmed) return null;
  // Only allow a safe charset; this also rejects path traversal (no / \ ..).
  if (!/^[A-Za-z0-9._-]+$/.test(trimmed)) return null;
  if (trimmed === '.' || trimmed === '..') return null;
  if (trimmed.length > 128) return null;
  return trimmed;
}

function extractFindings(scan) {
  if (!scan) return [];
  if (Array.isArray(scan)) return scan;
  if (Array.isArray(scan.findings)) return scan.findings;
  return [];
}

function countSeverities(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    const sev = String(f && f.severity || '').toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, sev)) {
      counts[sev]++;
    }
    counts.total++;
  }
  return counts;
}

function topRules(findings, n) {
  const m = new Map();
  for (const f of findings) {
    const r = (f && f.rule) ? String(f.rule) : '(unknown)';
    m.set(r, (m.get(r) || 0) + 1);
  }
  return [...m.entries()]
    .map(([rule, count]) => ({ rule, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

function timingSafeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function checkAuth(req) {
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return false;
  return timingSafeEqual(m[1].trim(), AUTH_TOKEN);
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('payload too large'), { code: 'TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function hostFilePath(safeName) {
  const p = path.join(DATA_DIR, safeName + '.json');
  // Defense in depth: ensure resolved path stays inside DATA_DIR.
  const resolved = path.resolve(p);
  if (resolved !== p || path.dirname(resolved) !== path.resolve(DATA_DIR)) {
    return null;
  }
  return p;
}

function loadHostRecord(safeName) {
  const p = hostFilePath(safeName);
  if (!p) return null;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (_) {
    return null;
  }
}

function listHostRecords() {
  let files;
  try { files = fs.readdirSync(DATA_DIR); } catch (_) { return []; }
  const out = [];
  for (const f of files) {
    if (!f.endsWith('.json')) continue;
    const safe = sanitizeHostname(f.slice(0, -5));
    if (!safe) continue;
    const rec = loadHostRecord(safe);
    if (rec) out.push(rec);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------
async function handleIngest(req, res) {
  if (!checkAuth(req)) {
    return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  }
  let raw;
  try {
    raw = await readBody(req, MAX_BODY);
  } catch (e) {
    if (e.code === 'TOO_LARGE') return sendJson(res, 413, { ok: false, error: 'payload too large' });
    return sendJson(res, 400, { ok: false, error: 'read error' });
  }

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (_) {
    return sendJson(res, 400, { ok: false, error: 'invalid JSON' });
  }

  const safe = sanitizeHostname(payload && payload.hostname);
  if (!safe) {
    return sendJson(res, 400, { ok: false, error: 'invalid hostname' });
  }

  const findings = extractFindings(payload.scan);
  const counts = countSeverities(findings);
  const tr = topRules(findings, 5);
  const scannedAt = (typeof payload.scannedAt === 'string' && payload.scannedAt) || new Date().toISOString();

  const existing = loadHostRecord(safe) || { history: [] };
  const history = Array.isArray(existing.history) ? existing.history : [];
  history.push({ timestamp: scannedAt, counts });
  while (history.length > HISTORY_LEN) history.shift();

  const record = {
    hostname: safe,
    lastSeen: scannedAt,
    counts,
    topRules: tr,
    findings,
    history,
  };

  const p = hostFilePath(safe);
  if (!p) return sendJson(res, 400, { ok: false, error: 'invalid hostname' });
  try {
    fs.writeFileSync(p, JSON.stringify(record, null, 2));
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'write failed' });
  }
  return sendJson(res, 200, { ok: true });
}

function handleHosts(req, res) {
  const recs = listHostRecords();
  const out = recs.map((r) => ({
    hostname: r.hostname,
    lastSeen: r.lastSeen,
    counts: r.counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    topRules: r.topRules || [],
  }));
  out.sort((a, b) => (b.counts.critical - a.counts.critical) || (b.counts.high - a.counts.high));
  return sendJson(res, 200, out);
}

function handleHost(req, res, name) {
  const safe = sanitizeHostname(decodeURIComponent(name));
  if (!safe) return sendJson(res, 400, { ok: false, error: 'invalid hostname' });
  const rec = loadHostRecord(safe);
  if (!rec) return sendJson(res, 404, { ok: false, error: 'not found' });
  return sendJson(res, 200, {
    hostname: rec.hostname,
    lastSeen: rec.lastSeen,
    counts: rec.counts,
    findings: rec.findings || [],
    history: rec.history || [],
  });
}

function serveIndex(res) {
  const p = path.join(PUBLIC_DIR, 'index.html');
  fs.readFile(p, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('index.html missing');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname;
  const method = req.method;

  if (method === 'POST' && pathname === '/api/ingest') {
    return handleIngest(req, res);
  }
  if (method === 'GET' && pathname === '/api/hosts') {
    return handleHosts(req, res);
  }
  const hostMatch = /^\/api\/host\/([^/]+)$/.exec(pathname);
  if (method === 'GET' && hostMatch) {
    return handleHost(req, res, hostMatch[1]);
  }
  if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    return serveIndex(res);
  }
  return sendJson(res, 404, { ok: false, error: 'not found' });
});

server.listen(PORT, HOST, () => {
  const u = `http://${HOST}:${PORT}/`;
  console.log('');
  console.log('  SentinelC Fleet Console');
  console.log('  -----------------------');
  console.log('  URL:    ' + u);
  console.log('  Token:  ' + AUTH_TOKEN + '  (source: ' + TOKEN_SOURCE + ')');
  console.log('  Data:   ' + DATA_DIR);
  console.log('');
  console.log('  Submit a scan with the Authorization: Bearer <token> header.');
  console.log('');
});
