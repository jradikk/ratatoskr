#!/usr/bin/env bash
# Create a Ratatoskr validation cluster on k3d.
#
# Usage: hack/k3d-up.sh <flannel|cilium|cilium-wg|calico> [--mesh=none|sidecar|ambient]
#
# Only one Ratatoskr cluster may exist at a time (the dev VM is small); tear the
# current one down with hack/k3d-down.sh before switching variants.
# Set FORCE=1 to skip the memory/CPU preflight.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=hack/versions.env
source "${ROOT}/hack/versions.env"

VARIANT="${1:-}"
MESH=none
for a in "${@:2}"; do
  case "$a" in
    --mesh=none|--mesh=sidecar|--mesh=ambient) MESH="${a#--mesh=}" ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done
CFG="${ROOT}/hack/k3d/${VARIANT}.yaml"
[[ -n "$VARIANT" && -f "$CFG" ]] || { echo "usage: $0 <flannel|cilium|cilium-wg|calico> [--mesh=none|sidecar|ambient]" >&2; exit 2; }
CLUSTER="ratatoskr-${VARIANT}"
CTX="k3d-${CLUSTER}"

log() { printf '\033[1;34m[k3d-up]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# k3s keeps CNI config/binaries here when a custom CNI replaces flannel.
K3S_CNI_CONF_DIR=/var/lib/rancher/k3s/agent/etc/cni/net.d
K3S_CNI_BIN_DIR=/var/lib/rancher/k3s/data/cni

preflight() {
  grep -qF "image: ${K3S_IMAGE}" "$CFG" || die "${CFG} image does not match K3S_IMAGE=${K3S_IMAGE} in hack/versions.env"

  local existing
  existing="$(k3d cluster list -o json | jq -r '.[].name | select(startswith("ratatoskr-"))')"
  if [[ "$existing" == "$CLUSTER" ]]; then
    log "cluster ${CLUSTER} already exists; reusing it"
    return 1
  fi
  [[ -z "$existing" ]] || die "another Ratatoskr cluster exists (${existing}); run hack/k3d-down.sh ${existing#ratatoskr-} first"

  # Rough working-set needs measured on k3d (1 server + 2 agents), MiB.
  local need=2200
  case "$VARIANT" in cilium|cilium-wg) need=$((need + 900)) ;; calico) need=$((need + 900)) ;; esac
  case "$MESH" in sidecar) need=$((need + 700)) ;; ambient) need=$((need + 900)) ;; esac
  local avail cpus
  avail=$(( $(awk '/MemAvailable/ {print $2}' /proc/meminfo) / 1024 ))
  cpus=$(nproc)
  log "preflight: ${avail} MiB available (need ~${need} MiB), ${cpus} CPUs"
  if [[ "${FORCE:-0}" != 1 ]]; then
    ((avail >= need)) || die "not enough memory for ${VARIANT}/mesh=${MESH}: ${avail} MiB available, ~${need} MiB needed (FORCE=1 to try anyway)"
    ((cpus >= 2)) || die "need at least 2 CPUs, have ${cpus}"
  fi
  for m in geneve wireguard tun; do
    [[ -d "/sys/module/${m}" ]] || grep -q "/${m}.ko" "/lib/modules/$(uname -r)/modules.builtin" \
      || die "kernel module ${m} not loaded; run hack/bootstrap.sh"
  done
  return 0
}

# Cilium needs bpffs and a cgroup2 mount with shared propagation inside every
# node container; k3d nodes do not have them by default.
prepare_nodes_for_cilium() {
  local n
  for n in $(k3d node list -o json | jq -r --arg c "$CLUSTER" '.[] | select(.runtimeLabels["k3d.cluster"]==$c and (.role=="server" or .role=="agent")) | .name'); do
    log "mounting bpffs and cgroup2 (shared) in ${n}"
    docker exec "$n" sh -ec '
      mountpoint -q /sys/fs/bpf || mount -t bpf bpffs /sys/fs/bpf
      mount --make-shared /sys/fs/bpf
      mkdir -p /run/cilium/cgroupv2
      mountpoint -q /run/cilium/cgroupv2 || mount -t cgroup2 none /run/cilium/cgroupv2
      mount --make-shared /run/cilium/cgroupv2
    '
  done
}

install_cilium() {
  prepare_nodes_for_cilium
  local server_ip extra=()
  server_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "k3d-${CLUSTER}-server-0")"
  if [[ "$VARIANT" == cilium-wg ]]; then
    extra+=(--set encryption.enabled=true --set encryption.type=wireguard)
  fi
  log "installing Cilium ${CILIUM_VERSION}"
  cilium install --context "$CTX" --version "${CILIUM_VERSION}" \
    --helm-values "${ROOT}/hack/k3d/cilium-values.yaml" \
    --set k8sServiceHost="${server_ip}" --set k8sServicePort=6443 \
    "${extra[@]}"
  cilium status --context "$CTX" --wait --wait-duration 10m
}

install_calico() {
  log "installing Calico ${CALICO_VERSION} via the Tigera operator"
  kubectl --context "$CTX" create -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/operator-crds.yaml" 2>/dev/null || true
  kubectl --context "$CTX" create -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml" 2>/dev/null || true
  kubectl --context "$CTX" -n tigera-operator rollout status deploy/tigera-operator --timeout=5m
  kubectl --context "$CTX" wait --for=condition=Established crd/installations.operator.tigera.io --timeout=2m
  kubectl --context "$CTX" apply -f "${ROOT}/hack/k3d/calico-installation.yaml"
  log "waiting for Calico to become available"
  kubectl --context "$CTX" wait --for=condition=Available tigerastatus/calico --timeout=10m
}

install_istio() {
  [[ "$MESH" == none ]] && return
  local args=(-y --context "$CTX")
  # istio-cni must use k3s's CNI locations.
  args+=(--set "values.cni.cniConfDir=${K3S_CNI_CONF_DIR}" --set "values.cni.cniBinDir=${K3S_CNI_BIN_DIR}")
  if [[ "$MESH" == sidecar ]]; then
    log "installing Istio ${ISTIO_VERSION} (sidecar mode, istio-cni)"
    args+=(--set profile=default --set components.cni.enabled=true)
  else
    log "installing Istio ${ISTIO_VERSION} (ambient mode)"
    args+=(--set profile=ambient)
  fi
  istioctl install "${args[@]}"
  kubectl --context "$CTX" -n istio-system rollout status deploy/istiod --timeout=5m
}

wait_nodes() {
  log "waiting for nodes to become Ready"
  kubectl --context "$CTX" wait --for=condition=Ready nodes --all --timeout=10m
}

main() {
  if preflight; then
    log "creating ${CLUSTER} (${K3S_IMAGE})"
    k3d cluster create --config "$CFG"
  fi
  kubectl config use-context "$CTX" >/dev/null
  case "$VARIANT" in
    cilium|cilium-wg) cilium status --context "$CTX" >/dev/null 2>&1 || install_cilium ;;
    calico) kubectl --context "$CTX" get tigerastatus calico >/dev/null 2>&1 || install_calico ;;
  esac
  wait_nodes
  if [[ "$MESH" != none ]] && ! kubectl --context "$CTX" get ns istio-system >/dev/null 2>&1; then
    install_istio
  fi
  kubectl --context "$CTX" create configmap -n kube-system ratatoskr-testenv \
    --from-literal=variant="$VARIANT" --from-literal=mesh="$MESH" \
    --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
  log "cluster ${CLUSTER} ready (context ${CTX}, mesh=${MESH})"
}

main
