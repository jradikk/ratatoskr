#!/usr/bin/env bash
# Tear down a Ratatoskr k3d cluster.
# Usage: hack/k3d-down.sh <flannel|cilium|cilium-wg|calico>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VARIANT="${1:-}"
[[ -n "$VARIANT" ]] || { echo "usage: $0 <flannel|cilium|cilium-wg|calico>" >&2; exit 2; }
[[ -f "${ROOT}/hack/k3d/${VARIANT}.yaml" ]] || { echo "unknown variant: ${VARIANT}" >&2; exit 2; }

CLUSTER="ratatoskr-${VARIANT}"
if k3d cluster list -o json | jq -e --arg c "$CLUSTER" 'any(.[]; .name==$c)' >/dev/null; then
  k3d cluster delete "$CLUSTER"
else
  echo "cluster ${CLUSTER} does not exist; nothing to do"
fi
