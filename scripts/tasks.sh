#!/usr/bin/env sh
# Task runner behind the Makefile. Usage: sh scripts/tasks.sh <target>
set -eu
cd "$(dirname "$0")/.."
DC="docker compose"
PY="$(command -v python3 || command -v python)"

wait_healthy() {
  echo "waiting for containers to become healthy..."
  i=0
  while [ $i -lt 90 ]; do
    unhealthy=$($DC ps --format '{{.Service}} {{.Health}}' | grep -v ' healthy$' || true)
    [ -z "$unhealthy" ] && { $DC ps --format 'table {{.Service}}\t{{.Status}}'; return 0; }
    i=$((i+1)); sleep 5
  done
  echo "not healthy in time:"; echo "$unhealthy"; $DC ps; return 1
}

case "${1:-help}" in
  env) "$PY" scripts/gen-env.py ;;
  up)
    [ -f .env ] || "$PY" scripts/gen-env.py
    $DC up -d --build
    wait_healthy ;;
  down) $DC --profile test down ;;
  ps) $DC ps ;;
  logs) $DC logs -f --tail=100 ;;
  qr) echo "Open http://127.0.0.1:8080/qr in a browser (or watch the logs below) and scan it from WhatsApp > Linked devices"; $DC logs -f wa-bridge ;;
  check-secrets) sh scripts/check-secrets.sh ;;
  test)
    sh scripts/check-secrets.sh
    $DC --profile test build tests
    $DC --profile test run --rm tests pytest -q \
      --cov=app --cov-config=/app/.coveragerc --cov-report=term-missing:skip-covered --cov-fail-under=90
    $DC --profile test run --rm tests sh -c \
      "pytest -q --cov=app --cov-branch --cov-config=/app/.coveragerc /repo/tests/unit/test_verdict.py >/dev/null && coverage report --include='*/verdict.py' --fail-under=100" ;;
  security)
    $DC --profile test up -d --build mock-bridge
    $DC --profile test run --rm tests pytest -q /repo/tests/security -m "not unit" -p no:cacheprovider ;;
  eval)
    $DC --profile test up -d --build mock-bridge
    $DC --profile test run --rm tests python /repo/tests/e2e/run_fixtures.py --report /repo/reports/eval.md ;;
  demo-fixtures)
    $DC --profile test run --rm tests python /repo/tests/fixtures/make_fixtures.py ;;
  export-workflows) "$PY" scripts/export_workflows.py ;;
  *) echo "targets: env up down ps logs qr test security eval demo-fixtures check-secrets export-workflows"; exit 2 ;;
esac
