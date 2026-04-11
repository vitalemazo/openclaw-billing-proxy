#!/bin/bash
# sync-claude-auth.sh
# Pulls fresh OAuth token from Tower cli-proxy-api into ~/.claude/.credentials.json
# Runs every 30 minutes via crontab on DGX Spark
# Crontab entry: */30 * * * * /opt/sync-claude-auth.sh

TOWER_PROXY="http://10.0.3.90:8317"
CREDENTIALS_FILE="$HOME/.claude/.credentials.json"
LOG_FILE="/tmp/sync-claude-auth.log"

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

token=$(curl -sf "$TOWER_PROXY/credentials" 2>/dev/null)
if [[ -z "$token" ]]; then
  echo "$(timestamp) ERROR: could not fetch token from $TOWER_PROXY" >> "$LOG_FILE"
  exit 1
fi

echo "$token" > "$CREDENTIALS_FILE"
echo "$(timestamp) OK: credentials synced from $TOWER_PROXY" >> "$LOG_FILE"
