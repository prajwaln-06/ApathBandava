#!/bin/sh
# n8n bootstrap: import credentials (rendered from env) + repo workflows, then start n8n.
# Workflows in n8n/workflows are the source of truth and are re-imported on every start.
set -e
umask 077
node /bootstrap/render-credentials.js > /tmp/creds.json
n8n import:credentials --input=/tmp/creds.json
rm -f /tmp/creds.json
n8n import:workflow --separate --input=/workflows
# n8n 2.x: workflows are activated by publishing. Publish every workflow whose JSON says active: true.
for f in /workflows/*.json; do
  id=$(node -e 'const w=require(process.argv[1]); if (w.active) process.stdout.write(w.id)' "$f")
  [ -n "$id" ] && n8n publish:workflow --id="$id" >/dev/null && echo "[bootstrap] published $(basename "$f")"
done
node /bootstrap/owner-setup.js &
exec tini -- /docker-entrypoint.sh
