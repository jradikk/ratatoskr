#!/usr/bin/env bash
# Initial manual live M1 harness; unset RATATOSKR_E2E_OVPN -> explicit skip.
# All executions are deferred until the final project gate.
set +x
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec bash "$ROOT/hack/m1-proof.sh" "$@" --mode=live
