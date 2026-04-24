#!/usr/bin/env node
// openai-proxy — Anthropic /v1/messages → OpenAI ChatCompletions translation,
// forwarded to the in-pod openai-oauth sidecar at 127.0.0.1:10531.
//
// Accepts: Anthropic `/v1/messages` shape from the llm-router.
// Emits:   Anthropic-shaped response.
// Does:    Translate shape + map model names + forward to sidecar.
//
// Phase 1 = non-streaming only. Streaming requests return 501.
//
// Design: docs/llm-router-architecture.md in dgx-spark-gitops.
// Extracted from billing-proxy v3.0.1's multi-provider routing block.

'use strict';

const http = require('http');
const crypto = require('crypto');

const VERSION = '0.4.0';

// ─── Configuration ────────────────────────────────────────────────
const PROXY_HOST = process.env.PROXY_HOST || '0.0.0.0';
const PROXY_PORT = parseInt(process.env.PROXY_PORT || '18801', 10);

const SIDECAR_HOST = process.env.OPENAI_SIDECAR_HOST || '127.0.0.1';
const SIDECAR_PORT = parseInt(process.env.OPENAI_SIDECAR_PORT || '10531', 10);
const SIDECAR_TIMEOUT_MS = parseInt(process.env.OPENAI_SIDECAR_TIMEOUT_MS || '120000', 10);

const DEFAULT_OPENAI_MODEL = process.env.DEFAULT_OPENAI_MODEL || 'gpt-5.4';

// ─── Tier vocabulary ──────────────────────────────────────────────
// Callers SHOULD send provider-agnostic tier names in the `model` field:
//   "flagship"  — reasoning-heavy (opus-tier)
//   "balanced"  — standard / production default (sonnet-tier)
//   "fast"      — cheap/quick (haiku-tier)
// Legacy provider-specific names remain supported via substring match
// below. Whatever the caller sends, this backend maps it to one of the
// sidecar's available models.
const TIER_TO_OPENAI = {
  flagship: process.env.OPENAI_MODEL_FLAGSHIP || 'gpt-5.5',
  balanced: process.env.OPENAI_MODEL_BALANCED || 'gpt-5.4',
  fast:     process.env.OPENAI_MODEL_FAST     || 'gpt-5.4-mini',
};

function normalizeTier(raw) {
  if (!raw) return 'balanced';
  const s = String(raw).toLowerCase();
  // Direct tier names
  if (s === 'flagship' || s === 'reasoning' || s === 'opus') return 'flagship';
  if (s === 'balanced' || s === 'standard' || s === 'sonnet' || s === 'default') return 'balanced';
  if (s === 'fast' || s === 'cheap' || s === 'quick' || s === 'haiku' || s === 'mini') return 'fast';
  // Legacy Anthropic names
  if (s.includes('opus'))   return 'flagship';
  if (s.includes('sonnet')) return 'balanced';
  if (s.includes('haiku'))  return 'fast';
  // Legacy OpenAI names
  if (s.includes('mini'))   return 'fast';
  if (s.includes('gpt-5.5')) return 'flagship';
  if (s.includes('gpt-5.4')) return 'balanced';
  if (s.includes('gpt-5'))   return 'balanced';
  return 'balanced';
}

// ─── Metrics ──────────────────────────────────────────────────────
const metrics = {
  // openai_proxy_requests_total{caller, model_in, model_out, status}
  requestsTotal: new Map(),
  // openai_proxy_upstream_duration_seconds{caller, model_out}
  durationBuckets: new Map(),
  // openai_proxy_translate_errors_total{direction, error_type}
  translateErrors: new Map(),
  // openai_proxy_tokens_approx_total{caller, model_out, direction} — char/4
  // estimates; surfaces in Grafana since ChatGPT OAuth returns 0 tokens.
  tokensApprox: new Map(),
  inFlight: 0,
};

function kv(labels) {
  return Object.entries(labels).sort().map(([k, v]) => `${k}="${v}"`).join(',');
}
function incCounter(map, labels, v = 1) {
  const k = kv(labels);
  map.set(k, (map.get(k) || 0) + v);
}
function observeHistogram(map, labels, seconds) {
  const k = kv(labels);
  const b = map.get(k) || { count: 0, sum: 0, buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120].map(le => ({ le, count: 0 })) };
  b.count += 1; b.sum += seconds;
  for (const x of b.buckets) if (seconds <= x.le) x.count += 1;
  map.set(k, b);
}
function renderPrometheus() {
  const L = [];
  L.push('# HELP openai_proxy_requests_total Translation+forward outcomes.');
  L.push('# TYPE openai_proxy_requests_total counter');
  for (const [k, v] of metrics.requestsTotal) L.push(`openai_proxy_requests_total{${k}} ${v}`);
  L.push('# HELP openai_proxy_upstream_duration_seconds Sidecar round-trip.');
  L.push('# TYPE openai_proxy_upstream_duration_seconds histogram');
  for (const [k, v] of metrics.durationBuckets) {
    for (const b of v.buckets) L.push(`openai_proxy_upstream_duration_seconds_bucket{${k},le="${b.le}"} ${b.count}`);
    L.push(`openai_proxy_upstream_duration_seconds_bucket{${k},le="+Inf"} ${v.count}`);
    L.push(`openai_proxy_upstream_duration_seconds_count{${k}} ${v.count}`);
    L.push(`openai_proxy_upstream_duration_seconds_sum{${k}} ${v.sum.toFixed(6)}`);
  }
  L.push('# HELP openai_proxy_translate_errors_total Request/response translation failures.');
  L.push('# TYPE openai_proxy_translate_errors_total counter');
  for (const [k, v] of metrics.translateErrors) L.push(`openai_proxy_translate_errors_total{${k}} ${v}`);
  L.push('# HELP openai_proxy_tokens_approx_total Approximate token counts (char/4) for the OpenAI path — ChatGPT OAuth does not surface real counts.');
  L.push('# TYPE openai_proxy_tokens_approx_total counter');
  for (const [k, v] of metrics.tokensApprox) L.push(`openai_proxy_tokens_approx_total{${k}} ${v}`);
  L.push('# HELP openai_proxy_requests_in_flight In-flight.');
  L.push('# TYPE openai_proxy_requests_in_flight gauge');
  L.push(`openai_proxy_requests_in_flight ${metrics.inFlight}`);
  L.push('# HELP openai_proxy_info Build info.');
  L.push('# TYPE openai_proxy_info gauge');
  L.push(`openai_proxy_info{version="${VERSION}",sidecar_host="${SIDECAR_HOST}",sidecar_port="${SIDECAR_PORT}"} 1`);
  return L.join('\n') + '\n';
}

// ─── Model resolution ─────────────────────────────────────────────
// Resolve whatever the caller sent into an OpenAI model name the
// sidecar can serve. Handles tier names, legacy Anthropic names, and
// legacy OpenAI names. Returns {tier, openaiModel}.
function resolveModel(raw) {
  // Sidecar-exposed models (per openai-oauth): gpt-5.5, gpt-5.4,
  // gpt-5.4-mini, gpt-5.3-codex, gpt-5.3-codex-spark, gpt-5.2,
  // codex-auto-review. If the caller sent ONE OF THOSE EXACTLY, we
  // pass it through — the caller is asking for a specific model
  // (probably a reasoning/codex variant) and tier remapping would
  // silently downgrade to gpt-5.4. Preserve caller intent.
  const s = String(raw || '').toLowerCase();
  const SIDECAR_EXACT = new Set([
    'gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini',
    'gpt-5.3-codex', 'gpt-5.3-codex-spark', 'gpt-5.2',
    'codex-auto-review',
  ]);
  if (SIDECAR_EXACT.has(s)) {
    return { tier: 'passthrough', openaiModel: raw };
  }
  const tier = normalizeTier(raw);
  return { tier, openaiModel: TIER_TO_OPENAI[tier] || DEFAULT_OPENAI_MODEL };
}

// ─── Request translation (Anthropic /v1/messages → OpenAI ChatCompletions) ─
function anthropicToOpenAIRequest(bodyStr) {
  const req = JSON.parse(bodyStr);
  const out = {
    model: resolveModel(req.model).openaiModel,
    messages: [],
  };

  if (typeof req.temperature === 'number') out.temperature = req.temperature;
  if (typeof req.top_p === 'number') out.top_p = req.top_p;
  if (typeof req.max_tokens === 'number') out.max_tokens = req.max_tokens;
  if (req.stream === true) out.stream = true;
  if (Array.isArray(req.stop_sequences) && req.stop_sequences.length > 0) {
    out.stop = req.stop_sequences;
  }

  if (req.system) {
    const sys = typeof req.system === 'string'
      ? req.system
      : (Array.isArray(req.system)
          ? req.system.map(p => (p && p.text) || '').filter(Boolean).join('\n\n')
          : '');
    if (sys) out.messages.push({ role: 'system', content: sys });
  }

  const messages = Array.isArray(req.messages) ? req.messages : [];
  for (const m of messages) {
    const role = m.role;
    const content = m.content;
    if (typeof content === 'string') {
      out.messages.push({ role, content });
      continue;
    }
    if (!Array.isArray(content)) {
      out.messages.push({ role, content: '' });
      continue;
    }

    const textParts = [];
    const toolCalls = [];
    const toolResults = [];
    for (const b of content) {
      if (!b || typeof b !== 'object') continue;
      if (b.type === 'text' && typeof b.text === 'string') {
        textParts.push(b.text);
      } else if (b.type === 'tool_use' && role === 'assistant') {
        toolCalls.push({
          id: b.id || ('call_' + crypto.randomBytes(8).toString('hex')),
          type: 'function',
          function: {
            name: b.name,
            arguments: typeof b.input === 'string' ? b.input : JSON.stringify(b.input || {}),
          },
        });
      } else if (b.type === 'tool_result') {
        toolResults.push({
          role: 'tool',
          tool_call_id: b.tool_use_id,
          content: typeof b.content === 'string'
            ? b.content
            : (Array.isArray(b.content)
                ? b.content.map(c => (c && c.text) || '').join('\n')
                : JSON.stringify(b.content || '')),
        });
      } else if (b.type === 'thinking') {
        continue;
      }
    }

    const msg = { role, content: textParts.join('') || null };
    if (toolCalls.length > 0) msg.tool_calls = toolCalls;
    out.messages.push(msg);
    for (const tr of toolResults) out.messages.push(tr);
  }

  if (Array.isArray(req.tools) && req.tools.length > 0) {
    out.tools = req.tools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description || '',
        parameters: t.input_schema || { type: 'object', properties: {} },
      },
    }));
  }
  if (req.tool_choice) {
    const tc = req.tool_choice;
    if (tc.type === 'auto') out.tool_choice = 'auto';
    else if (tc.type === 'any') out.tool_choice = 'required';
    else if (tc.type === 'tool' && tc.name) {
      out.tool_choice = { type: 'function', function: { name: tc.name } };
    }
  }

  return { body: JSON.stringify(out), model: out.model, stream: !!out.stream, originalModel: req.model };
}

// Token-count approximation for the OpenAI path.
//
// The openai-oauth sidecar (backed by ChatGPT OAuth) returns
// `usage: {prompt_tokens: 0, completion_tokens: 0, total_tokens: 0}` —
// the ChatGPT backend-api doesn't expose real counts. Downstream
// services read usage.*_tokens to populate llm_tokens_total, so without
// substitution every OpenAI-routed request counts as 0 tokens in
// Grafana and the burn panels under-count badly.
//
// Approximation: char/4 on the combined text content. OpenAI's public
// guidance says "1 token ≈ 4 chars in English" for gpt-family tokenizers.
// Not exact but gives a trendable signal. Tagged with `approx: true` in
// the response so downstream can distinguish estimates from truth.
function approxTokens(text) {
  if (!text) return 0;
  // Conservative round-up so zero-length text still reports 0 tokens
  // but anything non-trivial gets at least 1.
  return Math.ceil(text.length / 4);
}

// Extract all text content from a parsed Anthropic-shaped request body
// for input-token approximation. Walks messages[].content (string or
// block array) + top-level system.
function collectRequestText(reqObj) {
  if (!reqObj) return '';
  const parts = [];
  if (typeof reqObj.system === 'string') parts.push(reqObj.system);
  else if (Array.isArray(reqObj.system)) {
    for (const p of reqObj.system) if (p && typeof p.text === 'string') parts.push(p.text);
  }
  for (const m of (reqObj.messages || [])) {
    const c = m.content;
    if (typeof c === 'string') parts.push(c);
    else if (Array.isArray(c)) {
      for (const b of c) {
        if (!b || typeof b !== 'object') continue;
        if (typeof b.text === 'string') parts.push(b.text);
        if (b.type === 'tool_use' && b.input) parts.push(JSON.stringify(b.input));
        if (b.type === 'tool_result' && typeof b.content === 'string') parts.push(b.content);
      }
    }
  }
  return parts.join('\n');
}

// Extract the assistant's text content from a translated Anthropic
// response for output-token approximation.
function collectResponseText(respObj) {
  if (!respObj) return '';
  const parts = [];
  for (const b of (respObj.content || [])) {
    if (!b || typeof b !== 'object') continue;
    if (typeof b.text === 'string') parts.push(b.text);
    if (b.type === 'tool_use' && b.input) parts.push(JSON.stringify(b.input));
  }
  return parts.join('\n');
}

// ─── Response translation (OpenAI ChatCompletions → Anthropic /v1/messages) ─
function openAIToAnthropicResponse(respBodyStr, origModelName) {
  let resp;
  try { resp = JSON.parse(respBodyStr); } catch (_) { return respBodyStr; }
  if (!resp || resp.error) return respBodyStr;

  const choice = (Array.isArray(resp.choices) && resp.choices[0]) || {};
  const msg = choice.message || {};
  const contentBlocks = [];
  if (typeof msg.content === 'string' && msg.content.length > 0) {
    contentBlocks.push({ type: 'text', text: msg.content });
  }
  if (Array.isArray(msg.tool_calls)) {
    for (const tc of msg.tool_calls) {
      let parsed = {};
      if (tc.function && typeof tc.function.arguments === 'string') {
        try { parsed = JSON.parse(tc.function.arguments); } catch (_) { parsed = {}; }
      }
      contentBlocks.push({
        type: 'tool_use',
        id: tc.id,
        name: tc.function && tc.function.name,
        input: parsed,
      });
    }
  }

  const finishMap = {
    stop: 'end_turn',
    length: 'max_tokens',
    tool_calls: 'tool_use',
    content_filter: 'end_turn',
  };
  const stopReason = finishMap[choice.finish_reason] || 'end_turn';

  const out = {
    id: resp.id || ('msg_' + crypto.randomBytes(12).toString('hex')),
    type: 'message',
    role: 'assistant',
    model: origModelName || resp.model || 'unknown',
    content: contentBlocks,
    stop_reason: stopReason,
    stop_sequence: null,
    usage: {
      input_tokens: (resp.usage && resp.usage.prompt_tokens) || 0,
      output_tokens: (resp.usage && resp.usage.completion_tokens) || 0,
    },
  };
  return JSON.stringify(out);
}

// ─── Sidecar call ─────────────────────────────────────────────────
function callSidecar(translatedBody) {
  return new Promise((resolve) => {
    const buf = Buffer.from(translatedBody, 'utf8');
    const opts = {
      host: SIDECAR_HOST,
      port: SIDECAR_PORT,
      method: 'POST',
      path: '/v1/chat/completions',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': buf.length,
        'Accept': 'application/json',
      },
      timeout: SIDECAR_TIMEOUT_MS,
    };
    const start = process.hrtime.bigint();
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const dur = Number(process.hrtime.bigint() - start) / 1e9;
        resolve({
          status: res.statusCode || 0,
          body: Buffer.concat(chunks).toString('utf8'),
          dur,
        });
      });
    });
    req.on('timeout', () => req.destroy(new Error('sidecar_timeout')));
    req.on('error', (e) => resolve({ status: 0, error: e.message || 'network', dur: Number(process.hrtime.bigint() - start) / 1e9 }));
    req.write(buf);
    req.end();
  });
}

// ─── Request handler ──────────────────────────────────────────────
async function handleMessages(req, res, bodyBuf) {
  metrics.inFlight += 1;
  const caller = req.headers['x-router-caller'] || req.headers['x-caller'] || 'unknown';
  const bodyStr = bodyBuf.toString('utf8');

  // Check for streaming — phase 1 doesn't support it
  let parsed;
  try { parsed = JSON.parse(bodyStr); } catch (_) { parsed = {}; }
  if (parsed.stream === true) {
    metrics.inFlight -= 1;
    res.writeHead(501, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      type: 'error',
      error: { type: 'not_implemented', message: 'Streaming not yet supported via OpenAI backend. Set LLM_ROUTER_MODE=anthropic-* or wait for phase-2 SSE translation.' },
    }));
    return;
  }

  // Translate request
  let translated;
  try {
    translated = anthropicToOpenAIRequest(bodyStr);
  } catch (e) {
    incCounter(metrics.translateErrors, { direction: 'in', error_type: 'parse' });
    metrics.inFlight -= 1;
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      type: 'error',
      error: { type: 'invalid_request_error', message: 'Failed to translate Anthropic request: ' + e.message },
    }));
    return;
  }

  // Call sidecar
  const upstream = await callSidecar(translated.body);
  observeHistogram(metrics.durationBuckets, { caller, model_out: translated.model }, upstream.dur);

  if (upstream.status === 0) {
    metrics.inFlight -= 1;
    incCounter(metrics.requestsTotal, {
      caller,
      model_in: translated.originalModel || 'unknown',
      model_out: translated.model,
      status: '0',
    });
    res.writeHead(502, { 'Content-Type': 'application/json', 'x-openai-proxy-error': upstream.error || 'network' });
    res.end(JSON.stringify({
      type: 'error',
      error: { type: 'upstream_error', message: `openai-oauth sidecar unreachable: ${upstream.error}` },
    }));
    return;
  }

  // On non-2xx, pass through status + body (translated if possible)
  if (upstream.status >= 400) {
    metrics.inFlight -= 1;
    incCounter(metrics.requestsTotal, {
      caller,
      model_in: translated.originalModel || 'unknown',
      model_out: translated.model,
      status: String(upstream.status),
    });
    res.writeHead(upstream.status, { 'Content-Type': 'application/json' });
    res.end(upstream.body);
    return;
  }

  // Translate success response back to Anthropic shape
  let anthropicShaped;
  try {
    anthropicShaped = openAIToAnthropicResponse(upstream.body, translated.originalModel);
  } catch (e) {
    incCounter(metrics.translateErrors, { direction: 'out', error_type: 'parse' });
    metrics.inFlight -= 1;
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      type: 'error',
      error: { type: 'translate_error', message: 'Response translation failed: ' + e.message },
    }));
    return;
  }

  // Token-count approximation. ChatGPT OAuth backend doesn't surface
  // real token counts; substitute char/4 estimates so downstream
  // llm_tokens_total Prometheus counter isn't stuck at zero for the
  // entire OpenAI routing path. Mark as approximate so consumers can
  // distinguish.
  try {
    const reqObj = JSON.parse(bodyStr);
    const respObj = JSON.parse(anthropicShaped);
    if (respObj && respObj.usage && (respObj.usage.input_tokens === 0 && respObj.usage.output_tokens === 0)) {
      const approxIn = approxTokens(collectRequestText(reqObj));
      const approxOut = approxTokens(collectResponseText(respObj));
      respObj.usage.input_tokens = approxIn;
      respObj.usage.output_tokens = approxOut;
      respObj.usage.approx = true;  // signal to downstream: these are estimates
      anthropicShaped = JSON.stringify(respObj);
      // Also emit as Prometheus counter for the dashboard's approx panel.
      incCounter(metrics.tokensApprox, { caller, model_out: translated.model, direction: 'in' }, approxIn);
      incCounter(metrics.tokensApprox, { caller, model_out: translated.model, direction: 'out' }, approxOut);
    }
  } catch (_) {
    // If we can't parse, ship the translation verbatim — it's still valid.
  }

  metrics.inFlight -= 1;
  incCounter(metrics.requestsTotal, {
    caller,
    model_in: translated.originalModel || 'unknown',
    model_out: translated.model,
    status: '200',
  });
  // Internal debug headers (kept in logs only, not propagated to
  // callers — the router strips anything matching /^x-(openai|anthropic)-proxy-/).
  console.log(`[openai-proxy] ok caller=${caller} in=${translated.originalModel || '?'} out=${translated.model} dur=${upstream.dur.toFixed(3)}s`);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(anthropicShaped);
}

// ─── /v1/chat/completions handler (native OpenAI passthrough) ─────
// Callers like Recallium speak OpenAI shape directly. No
// Anthropic↔OpenAI translation needed — only model-name rewrite to
// produce a sidecar-valid model name. Body + response pass through
// unchanged. Streaming supported: if caller sets stream:true we pipe
// the SSE bytes straight from sidecar to caller.
async function handleChatCompletions(req, res, bodyBuf) {
  metrics.inFlight += 1;
  const caller = req.headers['x-router-caller'] || req.headers['x-caller'] || 'unknown';
  const bodyStr = bodyBuf.toString('utf8');

  let parsed;
  try { parsed = JSON.parse(bodyStr); } catch (e) {
    metrics.inFlight -= 1;
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { type: 'invalid_request_error', message: 'Invalid JSON body: ' + e.message } }));
    return;
  }
  const originalModel = parsed.model || '';
  const resolved = resolveModel(originalModel);
  parsed.model = resolved.openaiModel;
  const isStreaming = parsed.stream === true;
  const rewritten = JSON.stringify(parsed);
  const rewrittenBuf = Buffer.from(rewritten, 'utf8');

  const opts = {
    host: SIDECAR_HOST,
    port: SIDECAR_PORT,
    method: 'POST',
    path: '/v1/chat/completions',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': rewrittenBuf.length,
      'Accept': isStreaming ? 'text/event-stream' : 'application/json',
    },
    timeout: SIDECAR_TIMEOUT_MS,
  };

  const start = process.hrtime.bigint();
  const hreq = http.request(opts, (hres) => {
    const status = hres.statusCode || 0;
    // For streaming: pipe chunks straight to the caller, no buffering.
    if (isStreaming && status >= 200 && status < 300) {
      const respHeaders = {};
      for (const [k, v] of Object.entries(hres.headers)) {
        const lk = k.toLowerCase();
        if (lk === 'content-length') continue;
        respHeaders[k] = v;
      }
      res.writeHead(status, respHeaders);
      hres.pipe(res);
      hres.on('end', () => {
        const dur = Number(process.hrtime.bigint() - start) / 1e9;
        observeHistogram(metrics.durationBuckets, { caller, model_out: resolved.openaiModel }, dur);
        incCounter(metrics.requestsTotal, {
          caller,
          model_in: originalModel || 'unknown',
          model_out: resolved.openaiModel,
          status: String(status),
        });
        console.log(`[openai-proxy] stream-ok caller=${caller} in=${originalModel||'?'} out=${resolved.openaiModel} dur=${dur.toFixed(3)}s`);
        metrics.inFlight -= 1;
      });
      return;
    }
    // Non-streaming: buffer
    const chunks = [];
    hres.on('data', c => chunks.push(c));
    hres.on('end', () => {
      const dur = Number(process.hrtime.bigint() - start) / 1e9;
      const body = Buffer.concat(chunks).toString('utf8');
      observeHistogram(metrics.durationBuckets, { caller, model_out: resolved.openaiModel }, dur);
      incCounter(metrics.requestsTotal, {
        caller,
        model_in: originalModel || 'unknown',
        model_out: resolved.openaiModel,
        status: String(status),
      });
      // Approximate tokens for the /v1/chat/completions path as well.
      // Sidecar returns OpenAI usage {0,0,0} — same problem as /v1/messages.
      let finalBody = body;
      if (status >= 200 && status < 300) {
        try {
          const respObj = JSON.parse(body);
          if (respObj.usage && respObj.usage.prompt_tokens === 0 && respObj.usage.completion_tokens === 0) {
            // Text is in choices[].message.content for non-streaming
            const promptParts = (parsed.messages || []).map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content || '')).join('\n');
            const respText = (respObj.choices || []).map(c => (c.message && c.message.content) || '').join('\n');
            const approxIn = approxTokens(promptParts);
            const approxOut = approxTokens(respText);
            respObj.usage.prompt_tokens = approxIn;
            respObj.usage.completion_tokens = approxOut;
            respObj.usage.total_tokens = approxIn + approxOut;
            respObj.usage.approx = true;
            finalBody = JSON.stringify(respObj);
            incCounter(metrics.tokensApprox, { caller, model_out: resolved.openaiModel, direction: 'in' }, approxIn);
            incCounter(metrics.tokensApprox, { caller, model_out: resolved.openaiModel, direction: 'out' }, approxOut);
          }
        } catch (_) { /* pass through verbatim */ }
      }
      const respHeaders = {};
      for (const [k, v] of Object.entries(hres.headers)) {
        const lk = k.toLowerCase();
        if (lk === 'content-length' || lk === 'transfer-encoding') continue;
        respHeaders[k] = v;
      }
      res.writeHead(status, respHeaders);
      res.end(finalBody);
      console.log(`[openai-proxy] chat-ok caller=${caller} in=${originalModel||'?'} out=${resolved.openaiModel} status=${status} dur=${dur.toFixed(3)}s`);
      metrics.inFlight -= 1;
    });
  });
  hreq.on('timeout', () => hreq.destroy(new Error('sidecar_timeout')));
  hreq.on('error', (e) => {
    const dur = Number(process.hrtime.bigint() - start) / 1e9;
    observeHistogram(metrics.durationBuckets, { caller, model_out: resolved.openaiModel }, dur);
    incCounter(metrics.requestsTotal, {
      caller,
      model_in: originalModel || 'unknown',
      model_out: resolved.openaiModel,
      status: '0',
    });
    console.error(`[openai-proxy] chat-err caller=${caller} err=${e.message}`);
    metrics.inFlight -= 1;
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'upstream_error', message: `sidecar unreachable: ${e.message}` } }));
    }
  });
  hreq.write(rewrittenBuf);
  hreq.end();
}

// ─── /v1/responses handler — ChatGPT Codex "Responses API" ────────
// OpenClaw's "codex" provider (api=openai-codex-responses) sends
// requests here. Body shape is sidecar-native, not Anthropic and not
// chat-completions — it's ChatGPT's unified Responses API. Just
// rewrite model field (if caller sent a tier name) and stream-pipe
// everything else straight to sidecar's /v1/responses.
async function handleResponsesPassthrough(req, res, bodyBuf) {
  metrics.inFlight += 1;
  const caller = req.headers['x-router-caller'] || req.headers['x-caller'] || 'unknown';
  const bodyStr = bodyBuf.toString('utf8');

  let parsed;
  try { parsed = JSON.parse(bodyStr); } catch (e) {
    metrics.inFlight -= 1;
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { type: 'invalid_request_error', message: 'Invalid JSON: ' + e.message } }));
    return;
  }
  const originalModel = parsed.model || '';
  const resolved = resolveModel(originalModel);
  parsed.model = resolved.openaiModel;
  const isStreaming = parsed.stream === true;
  const rewritten = JSON.stringify(parsed);
  const rewrittenBuf = Buffer.from(rewritten, 'utf8');

  const opts = {
    host: SIDECAR_HOST,
    port: SIDECAR_PORT,
    method: 'POST',
    path: '/v1/responses',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': rewrittenBuf.length,
      'Accept': isStreaming ? 'text/event-stream' : 'application/json',
    },
    timeout: SIDECAR_TIMEOUT_MS,
  };

  const start = process.hrtime.bigint();
  const hreq = http.request(opts, (hres) => {
    const status = hres.statusCode || 0;
    // Streaming: pipe bytes straight
    if (isStreaming && status >= 200 && status < 300) {
      const respHeaders = {};
      for (const [k, v] of Object.entries(hres.headers)) {
        if (k.toLowerCase() === 'content-length') continue;
        respHeaders[k] = v;
      }
      res.writeHead(status, respHeaders);
      hres.pipe(res);
      hres.on('end', () => {
        const dur = Number(process.hrtime.bigint() - start) / 1e9;
        observeHistogram(metrics.durationBuckets, { caller, model_out: resolved.openaiModel }, dur);
        incCounter(metrics.requestsTotal, {
          caller, model_in: originalModel || 'unknown',
          model_out: resolved.openaiModel, status: String(status),
        });
        console.log(`[openai-proxy] responses-stream-ok caller=${caller} in=${originalModel||'?'} out=${resolved.openaiModel} dur=${dur.toFixed(3)}s`);
        metrics.inFlight -= 1;
      });
      return;
    }
    // Non-streaming: buffer + pass through
    const chunks = [];
    hres.on('data', c => chunks.push(c));
    hres.on('end', () => {
      const dur = Number(process.hrtime.bigint() - start) / 1e9;
      const body = Buffer.concat(chunks).toString('utf8');
      observeHistogram(metrics.durationBuckets, { caller, model_out: resolved.openaiModel }, dur);
      incCounter(metrics.requestsTotal, {
        caller, model_in: originalModel || 'unknown',
        model_out: resolved.openaiModel, status: String(status),
      });
      const respHeaders = {};
      for (const [k, v] of Object.entries(hres.headers)) {
        const lk = k.toLowerCase();
        if (lk === 'content-length' || lk === 'transfer-encoding') continue;
        respHeaders[k] = v;
      }
      res.writeHead(status, respHeaders);
      res.end(body);
      console.log(`[openai-proxy] responses-ok caller=${caller} in=${originalModel||'?'} out=${resolved.openaiModel} status=${status} dur=${dur.toFixed(3)}s`);
      metrics.inFlight -= 1;
    });
  });
  hreq.on('timeout', () => hreq.destroy(new Error('sidecar_timeout')));
  hreq.on('error', (e) => {
    console.error(`[openai-proxy] responses-err caller=${caller} err=${e.message}`);
    metrics.inFlight -= 1;
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { type: 'upstream_error', message: `sidecar unreachable: ${e.message}` } }));
    }
  });
  hreq.write(rewrittenBuf);
  hreq.end();
}

// ─── HTTP server ──────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  if (req.url === '/health' || req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      service: 'openai-proxy',
      version: VERSION,
      sidecar: `${SIDECAR_HOST}:${SIDECAR_PORT}`,
      default_model: DEFAULT_OPENAI_MODEL,
      in_flight: metrics.inFlight,
    }));
    return;
  }
  if (req.url === '/metrics') {
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
    res.end(renderPrometheus());
    return;
  }

  // Three POST endpoints:
  //   /v1/messages          — Anthropic shape, translates to OpenAI
  //   /v1/chat/completions  — OpenAI shape, passes through
  //   /v1/responses         — ChatGPT Codex Responses API, passes through
  const isMsg = (req.url === '/v1/messages' || req.url.startsWith('/v1/messages?')) && req.method === 'POST';
  const isChat = (req.url === '/v1/chat/completions' || req.url.startsWith('/v1/chat/completions?')) && req.method === 'POST';
  const isResponses = (req.url === '/v1/responses' || req.url.startsWith('/v1/responses?')) && req.method === 'POST';
  if (!isMsg && !isChat && !isResponses) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      type: 'error',
      error: { type: 'not_found', message: `openai-proxy handles POST /v1/messages, /v1/chat/completions, or /v1/responses; got ${req.method} ${req.url}` },
    }));
    return;
  }

  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    try {
      if (isChat) {
        await handleChatCompletions(req, res, Buffer.concat(chunks));
      } else if (isResponses) {
        await handleResponsesPassthrough(req, res, Buffer.concat(chunks));
      } else {
        await handleMessages(req, res, Buffer.concat(chunks));
      }
    } catch (e) {
      console.error('[openai-proxy] unhandled:', e.stack || e.message);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: 'internal error' } }));
      }
    }
  });
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log(`openai-proxy v${VERSION} listening on ${PROXY_HOST}:${PROXY_PORT}`);
  console.log(`  sidecar:       http://${SIDECAR_HOST}:${SIDECAR_PORT}`);
  console.log(`  default model: ${DEFAULT_OPENAI_MODEL}`);
  console.log(`  timeout:       ${SIDECAR_TIMEOUT_MS}ms`);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    console.log(`[${sig}] shutting down…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 15000).unref();
  });
}
