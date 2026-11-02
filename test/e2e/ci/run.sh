#!/usr/bin/env bash
# M8 inventory by default; missing/unimplemented coverage must never be green.
# Traffic execution requires --execute AND final-gate environment authorization.
set +x
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec python3 "$ROOT/test/e2e/matrix/run.py" "$@" --mode=fake
