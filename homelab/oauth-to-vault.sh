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

# Source env file FIRST so VAULT_ROLE_ID / VAULT_SECRET_ID are in scope.
if [ -f /boot/config/custom/oauth-to-vault.env ]; then
  # shellcheck disable=SC1091
  . /boot/config/custom/oauth-to-vault.env
fi

VAULT_ADDR="${VAULT_ADDR:-http://10.0.3.75:8200}"
ROLE_ID="${VAULT_ROLE_ID:-}"
SECRET_ID="${VAULT_SECRET_ID:-}"
VAULT_PATH="${VAULT_PATH:-secret/data/openclaw/claude-oauth}"
CRED_FILE="${CRED_FILE:-/mnt/user/appdata/cli-proxy-api/auth/claude-vitalemazo@gmail.com.json}"

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

# 2. Transform cli-proxy-api's flat schema to Claude CLI's nested shape that
#    openclaw-billing-proxy reads. See /opt/sync-claude-auth.sh on DGX for
#    the reference transform: billing-proxy reads creds.claudeAiOauth.{
#    accessToken, refreshToken, expiresAt } — the raw Tower file only has
#    flat snake_case fields. Without this transform, proxy.js logs
#    'No OAuth token. Run "claude auth login"' and refuses to start.
#
# expiresAt: epoch milliseconds. Tower stores `expired` as ISO8601 with a
# +HH:MM offset ("2026-04-22T07:27:24+08:00") which jq's fromdateiso8601
# can't parse (it wants Z). Use `date -d` which accepts both.
ACCESS=$(jq -r '.access_token' < "$CRED_FILE")
REFRESH=$(jq -r '.refresh_token' < "$CRED_FILE")
EXPIRED_ISO=$(jq -r '.expired' < "$CRED_FILE")
SUB_TYPE=$(jq -r '.type // "max"' < "$CRED_FILE")
EXPIRES_MS=$(date -d "$EXPIRED_ISO" +%s%3N)

if [ -z "$ACCESS" ] || [ -z "$REFRESH" ] || [ -z "$EXPIRES_MS" ] || [ "$EXPIRES_MS" = "" ]; then
  echo "[$(date)] FATAL: could not extract tokens from $CRED_FILE" >&2
  exit 6
fi

CC_FORMAT=$(jq -nc \
  --arg access "$ACCESS" --arg refresh "$REFRESH" --arg sub "$SUB_TYPE" \
  --argjson expires "$EXPIRES_MS" \
  '{claudeAiOauth: {accessToken: $access, refreshToken: $refresh, expiresAt: $expires, subscriptionType: $sub}}')

# Pack for Vault KV-v2 write: { data: { credentials: "<json-string>" } }.
# We store as a string so the pod mounts it verbatim as a single file.
PAYLOAD=$(echo "$CC_FORMAT" | jq -Rs '{data: {credentials: .}}')

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
