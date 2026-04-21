#!/bin/bash
# oauth-to-vault.sh — sync fresh Claude OAuth credentials to Vault
#
# Reads the credentials.json that cli-proxy-api keeps refreshed on Tower
# and writes it to Vault at secret/openclaw/claude-oauth every run.
# ESO on DGX k3s then syncs it into a k8s Secret that the openclaw-billing-proxy
# pod mounts as /root/.claude/.credentials.json.
#
# Schedule via root cron every 10 min (cli-proxy-api refreshes every 15 min,
# our 10-min cadence ensures fresh tokens land in Vault at least once per
# proxy refresh window).
#
# Runs on Unraid tower. Requires curl and jq.

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://10.0.3.75:8200}"
ROLE_ID="${VAULT_ROLE_ID:-}"
SECRET_ID="${VAULT_SECRET_ID:-}"
VAULT_PATH="${VAULT_PATH:-secret/data/openclaw/claude-oauth}"
CRED_FILE="${CRED_FILE:-/mnt/user/appdata/cli-proxy-api/auth/claude-vitalemazo@gmail.com.json}"

# Load creds from environment or from /boot/config/custom/oauth-to-vault.env
if [ -z "$ROLE_ID" ] && [ -f /boot/config/custom/oauth-to-vault.env ]; then
  # shellcheck disable=SC1091
  . /boot/config/custom/oauth-to-vault.env
fi

if [ -z "$ROLE_ID" ] || [ -z "$SECRET_ID" ]; then
  echo "[$(date)] FATAL: VAULT_ROLE_ID / VAULT_SECRET_ID not set" >&2
  exit 2
fi

if [ ! -r "$CRED_FILE" ]; then
  echo "[$(date)] FATAL: creds file $CRED_FILE missing or unreadable" >&2
  exit 3
fi

# 1. Fetch fresh Vault token via AppRole
TOKEN=$(curl -s --max-time 5 -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" \
  "$VAULT_ADDR/v1/auth/approle/login" \
  | jq -r '.auth.client_token // empty')

if [ -z "$TOKEN" ]; then
  echo "[$(date)] FATAL: AppRole login failed" >&2
  exit 4
fi

# 2. Pack the creds file as Vault KV-v2 data payload.
#    Vault wants {"data": {<key>: <value>}}. We put the RAW json under key
#    'credentials' so the consumer can mount it verbatim.
PAYLOAD=$(jq -Rs '{data: {credentials: .}}' < "$CRED_FILE")

# 3. Write to Vault. Merge with any existing keys at the path.
HTTP_CODE=$(curl -s -o /tmp/oauth-to-vault.resp -w '%{http_code}' \
  --max-time 5 -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$PAYLOAD" \
  "$VAULT_ADDR/v1/$VAULT_PATH")

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "204" ]; then
  echo "[$(date)] FATAL: Vault write returned HTTP $HTTP_CODE" >&2
  cat /tmp/oauth-to-vault.resp >&2
  exit 5
fi

echo "[$(date)] OK: wrote fresh creds to $VAULT_PATH (HTTP $HTTP_CODE)"
rm -f /tmp/oauth-to-vault.resp
