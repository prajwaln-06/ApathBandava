#!/usr/bin/env sh
# Fails if any staged/tracked file is a known secret file or contains key material.
# Used by the git pre-commit hook and by CI (`make check-secrets`).
set -eu
files=$( { git diff --cached --name-only --diff-filter=ACM 2>/dev/null; git ls-files; } | sort -u )
bad=0
for f in $files; do
  case "$f" in
    *.references|*credentials*.json|.env|*/.env|secrets/*) echo "BLOCKED secret file: $f"; bad=1; continue;;
  esac
  [ -f "$f" ] || continue
  if grep -IlE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' -e '"private_key_id"' -e 'AIza[0-9A-Za-z_-]{30,}' -e 'AQ\.[A-Za-z0-9_-]{30,}' -e 'sk-ant-[A-Za-z0-9_-]{20,}' "$f" >/dev/null 2>&1; then
    case "$f" in scripts/check-secrets.sh) ;; *) echo "BLOCKED key material in: $f"; bad=1;; esac
  fi
done
[ "$bad" -eq 0 ] && echo "check-secrets: OK" || { echo "check-secrets: FAILED"; exit 1; }
