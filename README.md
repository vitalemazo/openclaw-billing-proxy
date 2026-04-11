# openclaw-billing-proxy

Personal deployment of the OpenClaw subscription billing proxy on a DGX Spark homelab. Routes OpenClaw agent requests through Claude Max subscription billing instead of Extra Usage, using a 7-layer bidirectional request/response transformation pipeline.

**Blog post:** [How I Kept OpenClaw Alive After Anthropic Killed Third-Party Billing](https://vitalemazo.com/blog/openclaw-billing-proxy-seven-layer-bypass)

---

## My Deployment

Running on **DGX Spark (spanky1, ARM64, 10.0.128.196)** as a systemd service alongside the OpenClaw gateway. OAuth tokens are automatically kept fresh via a token renewal chain from my Tower Unraid server.

```
Tower (Unraid, 10.0.128.2)
  └── cli-proxy-api :8317  ← refreshes OAuth token every 15min
        │
        │  cron pull every 30min
        ▼
DGX Spark (10.0.128.196)
  └── ~/.claude/.credentials.json  (always fresh)
        │
        ▼
  openclaw-billing-proxy :18801  (systemd, this repo)
        │
        ▼
  openclaw-gateway :18789  (13 agents: main, trader, orchestrator, ...)
        │
        ▼
  api.anthropic.com  → billed to MAX subscription
```

13 active agents: `main` (sonnet-4-6), `trader` (opus-4-6), `orchestrator` (opus-4-6), `architect`, `developer`, `aws-expert`, `azure-expert`, `cloud-engineer`, `cloud-architect`, `platform-engineer`, `sentinel` (haiku), `scribe` (haiku), `project-manager`.

---

## What This Solves

On April 4, 2026 Anthropic revoked subscription billing for third-party AI harnesses. OpenClaw requests started hitting Extra Usage instead of the Max subscription. This proxy sits between OpenClaw and `api.anthropic.com` and performs 7-layer bidirectional transformation so requests look like native Claude Code sessions.

**Outbound (request to API):**
1. **Billing Header** — Injects 84-char SHA256 Claude Code billing identifier
2. **Token Swap** — Replaces OpenClaw's API key with your OAuth token
3. **String Sanitization** — 30 trigger phrase replacements (OpenClaw→ClaudeCode, sessions_*→thread_*, etc.)
4. **Tool Name Rename** — 31 OC snake_case tools → PascalCase CC convention (exec→Bash, lcm_read→FileRead, sessions_spawn→TaskSpawn, ...)
5. **System Template Strip** — Removes ~28K structured config sections, replaces with ~0.5K prose paraphrase
6. **Tool Description Strip** — Removes all tool descriptions to reduce fingerprint signal
7. **Property Rename** — 8 OC-specific schema properties renamed (session_id→thread_id, etc.)

**Inbound (response to OpenClaw):**

8. **Full Reverse Map** — Restores all original tool names, paths, and identifiers in both SSE chunks and JSON responses. OpenClaw sees its own world unchanged.

---

## Systemd Setup (Linux / DGX Spark)

```bash
# Clone
sudo git clone https://github.com/vitalemazo/openclaw-billing-proxy /opt/openclaw-billing-proxy
sudo chown -R $USER:$USER /opt/openclaw-billing-proxy

# Create service
sudo tee /etc/systemd/system/openclaw-billing-proxy.service > /dev/null << 'EOF'
[Unit]
Description=OpenClaw Billing Proxy
After=network.target
Wants=network.target

[Service]
Type=simple
User=ghost
ExecStart=/usr/bin/node /opt/openclaw-billing-proxy/proxy.js --port 18801
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now openclaw-billing-proxy
```

Verify:
```bash
curl http://127.0.0.1:18801/health
```

```json
{
  "status": "ok",
  "version": "2.2.3",
  "subscriptionType": "max",
  "tokenExpiresInHours": "7.7",
  "layers": {
    "stringReplacements": 30,
    "toolNameRenames": 31,
    "propertyRenames": 8,
    "systemStripEnabled": true,
    "descriptionStripEnabled": true
  }
}
```

---

## OpenClaw Configuration

In `~/.openclaw/openclaw.json`, point the `cli-proxy` provider at the proxy port and switch all agents off `claude-cli/` to `cli-proxy/`:

```json
{
  "models": {
    "providers": {
      "cli-proxy": {
        "baseUrl": "http://127.0.0.1:18801",
        "apiKey": "any-value-proxy-replaces-it",
        "api": "anthropic-messages",
        "models": [
          { "id": "claude-sonnet-4-6",        "name": "Claude Sonnet 4.6", "contextWindow": 200000, "maxTokens": 8192 },
          { "id": "claude-opus-4-6",           "name": "Claude Opus 4.6",   "contextWindow": 200000, "maxTokens": 8192 },
          { "id": "claude-haiku-4-5-20251001", "name": "Claude Haiku 4.5",  "contextWindow": 200000, "maxTokens": 8192 }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "cli-proxy/claude-sonnet-4-6"
      }
    }
  }
}
```

Then clear stale sessions and restart the gateway:

```bash
rm -f ~/.openclaw/agents/*/sessions/sessions.json
systemctl --user restart openclaw-gateway
```

---

## Automated Token Renewal

Claude Code OAuth tokens expire roughly every 8 hours. I keep them fresh without manual intervention using two components:

**On Tower (Unraid Docker container `cli-proxy-api`):**
Refreshes the OAuth token every 15 minutes automatically.

**On DGX Spark (crontab):**
```bash
# Pull fresh token from Tower every 30 minutes
*/30 * * * * /opt/sync-claude-auth.sh
```

`/opt/sync-claude-auth.sh` copies the current token from Tower's `cli-proxy-api` into `~/.claude/.credentials.json`. The proxy reads credentials fresh from disk on every request, so no proxy restart is needed after a token refresh.

Monitor token expiry via the health endpoint — alert when `tokenExpiresInHours` drops below 1.

---

## Requirements

- Node.js 18+
- Claude Max or Pro subscription
- Claude Code CLI installed and authenticated (`claude auth login`)
- OpenClaw gateway running

---

## Health Check

```bash
curl http://127.0.0.1:18801/health
```

Shows token status, subscription type, uptime, request count, and all layer configurations.

## Troubleshoot

```bash
node troubleshoot.js
```

Tests credentials, token validity, API connectivity, billing header, trigger detection, proxy health, and end-to-end in 8 independent checks.

---

## How Anthropic's Detection Works

Four cumulative layers score the entire request body:

| Layer | Type | Introduced |
|-------|------|------------|
| Billing header | String match on system prompt | Pre-April 4, 2026 |
| String triggers | Keyword scan (OpenClaw, sessions_*, HEARTBEAT, etc.) | Pre-April 4, 2026 |
| Tool name fingerprinting | OC snake_case tool set signature | April 8, 2026 |
| System prompt template | Structured config section shape | April 8, 2026 |

All four must be addressed simultaneously — the classifier scores the full request body and each signal contributes cumulatively.

---

## Proxy Code

Core proxy logic: [`proxy.js`](proxy.js) — zero dependencies, single file, ~800 lines. Works on Linux, macOS, Windows.

Original proxy implementation by the open-source community. MIT licensed — see [LICENSE](LICENSE).

---

## License

MIT — see [LICENSE](LICENSE).
