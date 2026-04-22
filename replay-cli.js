#!/usr/bin/env node
/**
 * replay-cli — fetch and pretty-print LLM transcripts from billing-proxy.
 *
 * Usage:
 *   BILLING_PROXY_URL=http://10.0.128.205:18801 replay-cli list [--limit 50]
 *   BILLING_PROXY_URL=http://10.0.128.205:18801 replay-cli show <request_id>
 *   BILLING_PROXY_URL=http://10.0.128.205:18801 replay-cli latest [--caller oc|plain]
 *
 * Used by Hermes/OpenClaw to pull the raw request and response body for a
 * specific LLM call when debugging odd model behavior. The billing-proxy
 * keeps the last 200 pairs in memory; older ones roll off.
 */

const http = require('http');

const BASE = process.env.BILLING_PROXY_URL || 'http://10.0.128.205:18801';

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
        try { resolve(JSON.parse(body)); } catch (e) { resolve(body); }
      });
    }).on('error', reject);
  });
}

function fmt(n) { return n == null ? '-' : String(n).padStart(6); }
function short(s, n) { return String(s || '').slice(0, n); }

async function cmdList(limit) {
  const data = await get(`${BASE}/replays?limit=${limit}`);
  console.log(`# ${data.count}/${data.cap} buffered replays\n`);
  console.log('id          ts                          caller  model                         status  dur(ms)  in_tok  out_tok');
  console.log('---------   --------------------------  ------  ----------------------------  ------  -------  ------  -------');
  for (const r of data.entries) {
    console.log(
      `${r.id}   ${r.ts}   ${short(r.caller, 6).padEnd(6)}  ${short(r.model, 28).padEnd(28)}  ${fmt(r.status)}  ${fmt(r.duration_ms)}  ${fmt(r.prompt_tokens)}  ${fmt(r.completion_tokens)}`
    );
  }
}

async function cmdShow(id) {
  const r = await get(`${BASE}/replays/${id}`);
  console.log(`# request_id: ${r.id}`);
  console.log(`# ts:         ${r.ts}`);
  console.log(`# caller:     ${r.caller}`);
  console.log(`# model:      ${r.model}`);
  console.log(`# ${r.method} ${r.url} → ${r.status}`);
  console.log(`# duration:   ${r.duration_ms}ms`);
  console.log(`# tokens:     ${r.prompt_tokens}/${r.completion_tokens} (in/out)`);
  console.log('\n─── REQUEST ─────────────────────────────────────────────');
  try { console.log(JSON.stringify(JSON.parse(r.request), null, 2)); }
  catch { console.log(r.request); }
  console.log('\n─── RESPONSE ────────────────────────────────────────────');
  try { console.log(JSON.stringify(JSON.parse(r.response), null, 2)); }
  catch { console.log(r.response); }
}

async function cmdLatest(caller) {
  const data = await get(`${BASE}/replays?limit=200`);
  const filtered = caller ? data.entries.filter((e) => e.caller === caller) : data.entries;
  if (!filtered.length) { console.log(`no replays${caller ? ` for caller=${caller}` : ''}`); return; }
  const latest = filtered[filtered.length - 1];
  await cmdShow(latest.id);
}

async function main() {
  const [, , cmd, ...args] = process.argv;
  const argMap = Object.fromEntries(args.filter(a => a.startsWith('--')).map(a => {
    const [k, v] = a.slice(2).split('=');
    return [k, v ?? args[args.indexOf(a) + 1]];
  }));
  const positional = args.filter(a => !a.startsWith('--'));

  try {
    if (cmd === 'list') await cmdList(argMap.limit || 50);
    else if (cmd === 'show') await cmdShow(positional[0]);
    else if (cmd === 'latest') await cmdLatest(argMap.caller);
    else {
      console.log('Usage: replay-cli {list|show <id>|latest [--caller oc|plain]} [--limit N]');
      console.log(`Target: ${BASE}`);
      process.exit(1);
    }
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }
}

main();
