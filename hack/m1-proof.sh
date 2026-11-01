#!/usr/bin/env bash
# Direct-config subset entrypoint; explicit final-gate authorization is required.
set +x
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v timeout >/dev/null || { printf '%s\n' 'GNU timeout is required' >&2; exit 2; }
# Global bound plus a separate cleanup grace. Each network/cluster action is also
# bounded by the harness; do not use SIGKILL as normal termination.
SECONDS_LIMIT=${M1_TOTAL_TIMEOUT_SECONDS:-1800}
[[ "$SECONDS_LIMIT" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' 'invalid total timeout' >&2; exit 2; }
exec timeout --signal=TERM --kill-after=270s "${SECONDS_LIMIT}s" \
  bash "$ROOT/test/e2e/m1/run.sh" "$@"
