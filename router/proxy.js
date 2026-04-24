#!/usr/bin/env node
// llm-router — thin provider-selection + fallback layer.
//
// Accepts Anthropic /v1/messages shape. Forwards to one of:
//   LLM_ROUTER_ANTHROPIC_URL  (the anthropic-proxy backend)
//   LLM_ROUTER_OPENAI_URL     (the openai-proxy backend)
// based on LLM_ROUTER_MODE. On failure of the primary, optionally
// falls through to the other backend (primary/only variants).
//
// Stateless. No cloaking. No translation. No OAuth. Just routing.
//
// Design: docs/llm-router-architecture.md in the dgx-spark-gitops repo.
// Replaces billing-proxy v3.0.1's monolithic routing block.

'use strict';

const http = require('http');
const url = require('url');
const crypto = require('crypto');

const VERSION = '0.4.0';

// ─── Configuration ────────────────────────────────────────────────
const PROXY_HOST = process.env.PROXY_HOST || '0.0.0.0';
const PROXY_PORT = parseInt(process.env.PROXY_PORT || '18801', 10);

// Mode enum:
//   openai-primary    (default) — OpenAI first, Anthropic fallback
//   anthropic-primary           — Anthropic first, OpenAI fallback
//   openai-only                 — OpenAI, no fallback
//   anthropic-only              — Anthropic, no fallback
const MODE = (process.env.LLM_ROUTER_MODE || 'openai-primary').toLowerCase();
const VALID_MODES = new Set(['openai-primary', 'anthropic-primary', 'openai-only', 'anthropic-only']);
if (!VALID_MODES.has(MODE)) {
  console.error(`[CONFIG] invalid LLM_ROUTER_MODE=${MODE}, must be one of ${[...VALID_MODES].join(', ')}`);
  process.exit(2);
}

const ANTHROPIC_URL = process.env.LLM_ROUTER_ANTHROPIC_URL || 'http://anthropic-proxy.llm-proxy.svc.cluster.local:18801';
const OPENAI_URL = process.env.LLM_ROUTER_OPENAI_URL || 'http://openai-proxy.llm-proxy.svc.cluster.local:18801';
const FAILOVER_TIMEOUT_MS = parseInt(process.env.LLM_ROUTER_FAILOVER_TIMEOUT_MS || '60000', 10);

// ─── Metrics ──────────────────────────────────────────────────────
const metrics = {
  // llm_router_requests_total{provider, caller, model, status, outcome}
  requestsTotal: new Map(),
  // llm_router_backend_duration_seconds{provider, caller, model}
  backendDurationBuckets: new Map(),
  // llm_router_fallback_events_total{from_provider, error_type}
  fallbackTotal: new Map(),
  // gauge — in-flight router requests
  inFlight: 0,
};

function counterKey(name, labels) {
  const labelStr = Object.entries(labels).sort().map(([k, v]) => `${k}="${v}"`).join(',');
  return `${name}{${labelStr}}`;
}

function incCounter(map, labels, v = 1) {
  const key = counterKey('x', labels);
  map.set(key, (map.get(key) || 0) + v);
}

function observeHistogram(map, labels, seconds) {
  const key = counterKey('x', labels);
  const bucket = map.get(key) || { count: 0, sum: 0, buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60].map(le => ({ le, count: 0 })) };
  bucket.count += 1;
  bucket.sum += seconds;
  for (const b of bucket.buckets) if (seconds <= b.le) b.count += 1;
  map.set(key, bucket);
}

function renderPrometheus() {
  const lines = [];
  lines.push(`# HELP llm_router_requests_total Total router requests by provider/outcome.`);
  lines.push(`# TYPE llm_router_requests_total counter`);
  for (const [key, v] of metrics.requestsTotal) {
    lines.push(`llm_router_requests_total${key.replace(/^x/, '')} ${v}`);
  }
  lines.push(`# HELP llm_router_backend_duration_seconds Router → backend round-trip.`);
  lines.push(`# TYPE llm_router_backend_duration_seconds histogram`);
  for (const [key, v] of metrics.backendDurationBuckets) {
    const labelStr = key.replace(/^x/, '').replace(/^\{|\}$/g, '');
    for (const b of v.buckets) {
      lines.push(`llm_router_backend_duration_seconds_bucket{${labelStr},le="${b.le}"} ${b.count}`);
    }
    lines.push(`llm_router_backend_duration_seconds_bucket{${labelStr},le="+Inf"} ${v.count}`);
    lines.push(`llm_router_backend_duration_seconds_count{${labelStr}} ${v.count}`);
    lines.push(`llm_router_backend_duration_seconds_sum{${labelStr}} ${v.sum.toFixed(6)}`);
  }
  lines.push(`# HELP llm_router_fallback_events_total Failover events.`);
  lines.push(`# TYPE llm_router_fallback_events_total counter`);
  for (const [key, v] of metrics.fallbackTotal) {
    lines.push(`llm_router_fallback_events_total${key.replace(/^x/, '')} ${v}`);
  }
  lines.push(`# HELP llm_router_requests_in_flight In-flight requests.`);
  lines.push(`# TYPE llm_router_requests_in_flight gauge`);
  lines.push(`llm_router_requests_in_flight ${metrics.inFlight}`);
  lines.push(`# HELP llm_router_info Router build info.`);
  lines.push(`# TYPE llm_router_info gauge`);
  lines.push(`llm_router_info{version="${VERSION}",mode="${MODE}"} 1`);
  return lines.join('\n') + '\n';
}

// ─── Helpers ──────────────────────────────────────────────────────
function extractCaller(headers) {
  // Preserve billing-proxy's caller-label convention for dashboard continuity.
  return headers['x-caller'] || headers['x-proxy-caller'] || 'unknown';
}

function extractModel(bodyStr) {
  try {
    const parsed = JSON.parse(bodyStr);
    return parsed.model || 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

function isAnthropicMessages(urlPath) {
  return urlPath === '/v1/messages' || urlPath.startsWith('/v1/messages?');
}

// /v1/chat/completions is the OpenAI-compat path. Callers like Recallium
// send OpenAI-shaped bodies here with claude-* or tier model names. Both
// backends can serve it:
//   openai-proxy: forward to sidecar (native OpenAI format, model-name rewrite)
//   anthropic-proxy: translate OpenAI→Anthropic (inherited from v2.x)
function isOpenAIChatCompletions(urlPath) {
  return urlPath === '/v1/chat/completions' || urlPath.startsWith('/v1/chat/completions?');
}

// /v1/responses — ChatGPT's Codex/Responses unified API. OpenClaw's
// "codex" provider (api=openai-codex-responses) sends here. Only
// openai-proxy can serve this; anthropic has no equivalent.
function isOpenAIResponses(urlPath) {
  return urlPath === '/v1/responses' || urlPath.startsWith('/v1/responses?');
}

// Any path the router should route through primary/fallback rather than
// passthrough. Non-routed paths (e.g., /v1/models) still passthrough to
// anthropic since it's the metadata source.
function isRoutedPath(urlPath) {
  return isAnthropicMessages(urlPath) || isOpenAIChatCompletions(urlPath) || isOpenAIResponses(urlPath);
}

// Paths that only the OpenAI backend can serve (no anthropic fallback).
function isOpenAIOnlyPath(urlPath) {
  return isOpenAIResponses(urlPath);
}

function parseBackendURL(urlStr) {
  const u = url.parse(urlStr);
  return {
    host: u.hostname,
    port: parseInt(u.port || '80', 10),
    pathPrefix: u.pathname === '/' || !u.pathname ? '' : u.pathname.replace(/\/$/, ''),
  };
}

// ─── Forward to backend ───────────────────────────────────────────
function forwardToBackend(backendURL, method, reqPath, headers, bodyBuf, provider, caller, model, ctx) {
  return new Promise((resolve) => {
    const backend = parseBackendURL(backendURL);
    const outHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'content-length' || lk === 'connection') continue;
      outHeaders[k] = v;
    }
    outHeaders['x-provider-source'] = provider;
    outHeaders['x-router-caller'] = caller;
    outHeaders['Content-Length'] = bodyBuf.length;

    const opts = {
      host: backend.host,
      port: backend.port,
      method,
      path: backend.pathPrefix + reqPath,
      headers: outHeaders,
      timeout: FAILOVER_TIMEOUT_MS,
    };

    const start = process.hrtime.bigint();
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        const dur = Number(process.hrtime.bigint() - start) / 1e9;
        observeHistogram(metrics.backendDurationBuckets, { provider, caller, model }, dur);
        resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, headers: res.headers, body, dur });
      });
    });
    req.on('timeout', () => { req.destroy(new Error('backend_timeout')); });
    req.on('error', (e) => {
      const dur = Number(process.hrtime.bigint() - start) / 1e9;
      observeHistogram(metrics.backendDurationBuckets, { provider, caller, model }, dur);
      resolve({ ok: false, status: 0, error: e.message || 'network', dur });
    });
    if (bodyBuf.length > 0) req.write(bodyBuf);
    req.end();
  });
}

function shouldFailover(result) {
  // Triggers: upstream 5xx, 429, network error, timeout. NOT: 4xx (caller
  // error — same on other provider), 3xx.
  if (!result.ok) {
    if (result.status === 0) return true; // network / timeout
    if (result.status >= 500) return true;
    if (result.status === 429) return true;
    return false; // 4xx — do not failover
  }
  return false;
}

function failoverErrorType(result) {
  if (result.status === 0) return result.error || 'network';
  if (result.status === 429) return 'rate_limit';
  if (result.status >= 500) return `upstream_${result.status}`;
  return `upstream_${result.status}`;
}

// ─── Primary router logic ─────────────────────────────────────────
async function route(req, res, bodyBuf) {
  metrics.inFlight += 1;
  const caller = extractCaller(req.headers);
  const bodyStr = bodyBuf.toString('utf8');
  const model = extractModel(bodyStr);

  let primary, secondary;
  if (MODE === 'openai-primary' || MODE === 'openai-only') {
    primary = { provider: 'openai', url: OPENAI_URL };
    secondary = MODE === 'openai-primary' ? { provider: 'anthropic', url: ANTHROPIC_URL } : null;
  } else {
    primary = { provider: 'anthropic', url: ANTHROPIC_URL };
    secondary = MODE === 'anthropic-primary' ? { provider: 'openai', url: OPENAI_URL } : null;
  }

  // OpenAI-only paths (e.g., /v1/responses) have no anthropic equivalent.
  // Force primary = openai and disable fallback regardless of MODE.
  if (isOpenAIOnlyPath(req.url)) {
    primary = { provider: 'openai', url: OPENAI_URL };
    secondary = null;
  }

  // Try primary
  const r1 = await forwardToBackend(primary.url, req.method, req.url, req.headers, bodyBuf, primary.provider, caller, model);
  if (r1.ok) {
    respondWith(res, r1, primary.provider, 'primary_ok', caller, model);
    metrics.inFlight -= 1;
    return;
  }

  // Primary failed. Decide on fallback.
  if (!secondary || !shouldFailover(r1)) {
    const outcome = secondary ? 'primary_only_fail' : (MODE.endsWith('-only') ? 'primary_only_fail' : 'primary_fail_no_fallback');
    respondWith(res, r1, primary.provider, outcome, caller, model);
    metrics.inFlight -= 1;
    return;
  }

  // Record the failover event
  incCounter(metrics.fallbackTotal, { from_provider: primary.provider, error_type: failoverErrorType(r1) });
  console.error(`[FAILOVER] ${primary.provider}→${secondary.provider}: status=${r1.status} error=${r1.error || '-'}`);

  // Try secondary
  const r2 = await forwardToBackend(secondary.url, req.method, req.url, req.headers, bodyBuf, secondary.provider, caller, model);
  if (r2.ok) {
    respondWith(res, r2, secondary.provider, 'primary_fail_fallback_ok', caller, model);
    metrics.inFlight -= 1;
    return;
  }

  // Both failed
  respondWith(res, r2, secondary.provider, 'primary_fail_fallback_fail', caller, model);
  metrics.inFlight -= 1;
}

function respondWith(res, backendResult, provider, outcome, caller, model) {
  const labels = { provider, caller, model, status: String(backendResult.status || 0), outcome };
  incCounter(metrics.requestsTotal, labels);

  const headers = {};
  for (const [k, v] of Object.entries(backendResult.headers || {})) {
    const lk = k.toLowerCase();
    // Hop-by-hop — we recompute these
    if (lk === 'content-length' || lk === 'connection' || lk === 'keep-alive' || lk === 'transfer-encoding') continue;
    // Backend-internal debug headers — do not leak to callers. Each
    // backend emits its own debug into /metrics + stdout logs for
    // operator use; callers only need the router's stamp.
    if (lk.startsWith('x-openai-proxy-') || lk.startsWith('x-anthropic-proxy-')) continue;
    if (lk.startsWith('x-debug-')) continue;
    headers[k] = v;
  }
  // Stamp provenance — the caller-facing truth, nothing else
  headers['x-proxy-provider'] = provider;
  headers['x-proxy-outcome'] = outcome;
  headers['x-proxy-router-version'] = VERSION;

  if (backendResult.body) {
    res.writeHead(backendResult.status || 502, headers);
    res.end(backendResult.body);
  } else {
    // Network failure with no body — synthesize JSON error
    res.writeHead(502, { 'Content-Type': 'application/json', 'x-proxy-provider': provider, 'x-proxy-outcome': outcome });
    res.end(JSON.stringify({
      type: 'error',
      error: {
        type: 'upstream_error',
        message: `Backend ${provider} unreachable: ${backendResult.error || 'unknown'}`,
      },
    }));
  }
}

// ─── /v1/models — synthetic model catalog ────────────────────────
// Serves tier names as the primary options so OpenAI-compat UIs
// (Recallium, LibreChat, etc.) that auto-discover models see the
// right vocabulary in their dropdowns. Legacy claude-* aliases
// included for backward compat; sidecar-specific gpt-5.x names
// included so direct-OpenAI callers see what's actually available.
function openAIModelsResponse() {
  const now = Math.floor(Date.now() / 1000);
  const models = [
    // Tier names — preferred vocabulary. Router maps to real backend
    // per LLM_ROUTER_MODE. These are what new configs should pick.
    { id: 'flagship', object: 'model', created: now, owned_by: 'llm-router', description: 'Reasoning-heavy tier — opus/gpt-5.5 class' },
    { id: 'balanced', object: 'model', created: now, owned_by: 'llm-router', description: 'Production default — sonnet/gpt-5.4 class' },
    { id: 'fast',     object: 'model', created: now, owned_by: 'llm-router', description: 'Cheap/quick — haiku/gpt-5.4-mini class' },
    // Legacy claude-* aliases — still supported, router infers tier
    // from substring (opus→flagship, sonnet→balanced, haiku→fast).
    { id: 'claude-opus-4-7',             object: 'model', created: now, owned_by: 'anthropic-legacy' },
    { id: 'claude-sonnet-4-6',           object: 'model', created: now, owned_by: 'anthropic-legacy' },
    { id: 'claude-haiku-4-5',            object: 'model', created: now, owned_by: 'anthropic-legacy' },
    // OpenAI direct names — when PROVIDER_PRIMARY=openai, these serve natively
    { id: 'gpt-5.5',      object: 'model', created: now, owned_by: 'openai-direct' },
    { id: 'gpt-5.4',      object: 'model', created: now, owned_by: 'openai-direct' },
    { id: 'gpt-5.4-mini', object: 'model', created: now, owned_by: 'openai-direct' },
  ];
  return { object: 'list', data: models };
}

function isModelsEndpoint(urlPath) {
  return urlPath === '/v1/models' || urlPath.startsWith('/v1/models?') || urlPath === '/models';
}

// ─── HTTP server ──────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  // /v1/models — synthetic catalog so UIs auto-discover tier names
  if (isModelsEndpoint(req.url) && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(openAIModelsResponse()));
    return;
  }

  // Health probe
  if (req.url === '/health' || req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      service: 'llm-router',
      version: VERSION,
      mode: MODE,
      in_flight: metrics.inFlight,
      backends: { anthropic: ANTHROPIC_URL, openai: OPENAI_URL },
    }));
    return;
  }

  // Prometheus metrics
  if (req.url === '/metrics') {
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
    res.end(renderPrometheus());
    return;
  }

  // Only POST /v1/messages is routed. Other paths pass through to anthropic
  // backend (which handles /v1/models, /v1/chat/completions, etc.) — this
  // keeps the router compatible with any non-messages endpoint that
  // anthropic-proxy exposes.
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const bodyBuf = Buffer.concat(chunks);

    // Only POST on routed paths (/v1/messages + /v1/chat/completions)
    // gets primary/fallback treatment. Everything else (GET /v1/models,
    // etc.) passthroughs to anthropic — that's the metadata source.
    if (!isRoutedPath(req.url) || req.method !== 'POST') {
      const caller = extractCaller(req.headers);
      const result = await forwardToBackend(ANTHROPIC_URL, req.method, req.url, req.headers, bodyBuf, 'anthropic', caller, 'passthrough');
      respondWith(res, result, 'anthropic', 'passthrough', caller, 'passthrough');
      return;
    }

    // Routed path — full primary/fallback logic
    try {
      await route(req, res, bodyBuf);
    } catch (e) {
      console.error(`[ROUTER] unhandled error: ${e.stack || e.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: 'router internal error' } }));
      }
    }
  });
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log(`llm-router v${VERSION} listening on ${PROXY_HOST}:${PROXY_PORT}`);
  console.log(`  mode:          ${MODE}`);
  console.log(`  anthropic →  ${ANTHROPIC_URL}`);
  console.log(`  openai    →  ${OPENAI_URL}`);
  console.log(`  failover timeout: ${FAILOVER_TIMEOUT_MS}ms`);
});

// Graceful shutdown
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    console.log(`[${sig}] shutting down…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 15000).unref();
  });
}
