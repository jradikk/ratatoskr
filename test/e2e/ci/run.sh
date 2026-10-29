#!/usr/bin/env bash
# Initial fake M1 CI harness, NOT a full M2-M9 suite or an enabled CI job.
# All executions are deferred until the final project gate.
set +x
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec bash "$ROOT/hack/m1-proof.sh" "$@" --mode=fake
