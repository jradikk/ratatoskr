#!/usr/bin/env bash
# Idempotent developer/CI bootstrap for Ratatoskr.
#
# Installs (only if missing or at the wrong version) everything needed to build,
# test and run the k3d validation environment, loads the required kernel modules
# and verifies the kernel baseline. Safe to re-run.
#
# Usage: hack/bootstrap.sh [--no-k8s-tools] [--no-kmod]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=hack/versions.env
source "${ROOT}/hack/versions.env"

WITH_K8S_TOOLS=1
WITH_KMOD=1
for a in "$@"; do
  case "$a" in
    --no-k8s-tools) WITH_K8S_TOOLS=0 ;;
    --no-kmod) WITH_KMOD=0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

BIN=/usr/local/bin
log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

SUDO=""
if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null || die "need root or sudo"
  SUDO="sudo"
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- kernel baseline -------------------------------------------------------
check_kernel() {
  local have want
  have="$(uname -r | cut -d- -f1)"
  want="${MIN_KERNEL}"
  if [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" != "$want" ]]; then
    die "kernel ${have} < required ${want}"
  fi
  ok "kernel $(uname -r) >= ${want}"
}

# --- download helpers ------------------------------------------------------
fetch() { curl -fsSL --retry 4 --retry-delay 2 -o "$2" "$1"; }

# verify <file> <expected-sha256>
verify() {
  local got
  got="$(sha256sum "$1" | awk '{print $1}')"
  [[ "$got" == "$2" ]] || die "checksum mismatch for $(basename "$1"): got $got want $2"
}

# sum_from_list <checksum-list-url> <asset-name>
sum_from_list() {
  # Match on basename: lists use "f", "*f", "./f" or "dir/f".
  curl -fsSL --retry 4 "$1" | awk -v f="$2" '{n=$2; sub(/^\*/, "", n); sub(/.*\//, "", n)} n==f {print $1}' | head -1
}

install_bin() { $SUDO install -m 0755 "$1" "${BIN}/$2"; }

# version_ok <cmd> <substring> : true when <cmd> output contains <substring>
version_ok() {
  command -v "$1" >/dev/null 2>&1 || return 1
  # Capture first: with pipefail, `grep -q` closing the pipe early would SIGPIPE the writer.
  local out
  out="$(eval "$2" 2>&1 || true)"
  grep -qF -- "$3" <<<"$out"
}

# --- apt packages ----------------------------------------------------------
APT_PKGS=(
  build-essential make git curl ca-certificates jq unzip
  clang llvm libbpf-dev bpftool linux-libc-dev
  wireguard-tools tcpdump nftables iproute2 ethtool conntrack
)

install_apt() {
  command -v apt-get >/dev/null || { log "apt-get not found; skipping distro packages"; return; }
  local missing=()
  for p in "${APT_PKGS[@]}"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
  done
  if ((${#missing[@]})); then
    log "installing apt packages: ${missing[*]}"
    $SUDO apt-get update -qq
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}"
  fi
  ok "distro packages"
  # Architecture-specific asm headers for BPF compilation (asm/types.h).
  local multiarch
  multiarch="$(gcc -print-multiarch 2>/dev/null || true)"
  if [[ -n "$multiarch" && ! -e /usr/include/asm && -d "/usr/include/${multiarch}/asm" ]]; then
    ok "asm headers at /usr/include/${multiarch}/asm (Makefile passes -I for bpf)"
  fi
}

# --- Go --------------------------------------------------------------------
install_go() {
  if version_ok /usr/local/go/bin/go "/usr/local/go/bin/go version" "go${GO_VERSION} "; then
    ok "go ${GO_VERSION}"; return
  fi
  log "installing go ${GO_VERSION}"
  local f="go${GO_VERSION}.linux-${ARCH}.tar.gz" sum
  sum="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' \
    | jq -r --arg f "$f" '.[].files[] | select(.filename==$f) | .sha256')"
  [[ -n "$sum" ]] || die "no checksum published for $f"
  fetch "https://go.dev/dl/${f}" "$TMP/$f"
  verify "$TMP/$f" "$sum"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "$TMP/$f"
  $SUDO ln -sf /usr/local/go/bin/go "${BIN}/go"
  $SUDO ln -sf /usr/local/go/bin/gofmt "${BIN}/gofmt"
  ok "go ${GO_VERSION}"
}

install_golangci_lint() {
  local v="${GOLANGCI_LINT_VERSION#v}"
  if version_ok golangci-lint "golangci-lint version" "${v}"; then ok "golangci-lint ${v}"; return; fi
  log "installing golangci-lint ${v}"
  local f="golangci-lint-${v}-linux-${ARCH}.tar.gz" base="https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_LINT_VERSION}"
  fetch "${base}/${f}" "$TMP/$f"
  verify "$TMP/$f" "$(sum_from_list "${base}/golangci-lint-${v}-checksums.txt" "$f")"
  tar -C "$TMP" -xzf "$TMP/$f"
  install_bin "$TMP/golangci-lint-${v}-linux-${ARCH}/golangci-lint" golangci-lint
  ok "golangci-lint ${v}"
}

# --- Kubernetes tooling ----------------------------------------------------
install_kubectl() {
  if version_ok kubectl "kubectl version --client" "${KUBECTL_VERSION}"; then ok "kubectl ${KUBECTL_VERSION}"; return; fi
  log "installing kubectl ${KUBECTL_VERSION}"
  local u="https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl"
  fetch "$u" "$TMP/kubectl"
  verify "$TMP/kubectl" "$(curl -fsSL "${u}.sha256")"
  install_bin "$TMP/kubectl" kubectl
  ok "kubectl ${KUBECTL_VERSION}"
}

install_helm() {
  if version_ok helm "helm version --short" "${HELM_VERSION}"; then ok "helm ${HELM_VERSION}"; return; fi
  log "installing helm ${HELM_VERSION}"
  local f="helm-${HELM_VERSION}-linux-${ARCH}.tar.gz"
  fetch "https://get.helm.sh/${f}" "$TMP/$f"
  verify "$TMP/$f" "$(curl -fsSL "https://get.helm.sh/${f}.sha256sum" | awk '{print $1}')"
  tar -C "$TMP" -xzf "$TMP/$f"
  install_bin "$TMP/linux-${ARCH}/helm" helm
  ok "helm ${HELM_VERSION}"
}

install_k3d() {
  if version_ok k3d "k3d version" "${K3D_VERSION}"; then ok "k3d ${K3D_VERSION}"; return; fi
  log "installing k3d ${K3D_VERSION}"
  local base="https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}" f="k3d-linux-${ARCH}"
  fetch "${base}/${f}" "$TMP/$f"
  verify "$TMP/$f" "$(sum_from_list "${base}/checksums.txt" "$f")"
  install_bin "$TMP/$f" k3d
  ok "k3d ${K3D_VERSION}"
}

install_cilium_cli() {
  if version_ok cilium "cilium version --client" "${CILIUM_CLI_VERSION}"; then ok "cilium-cli ${CILIUM_CLI_VERSION}"; return; fi
  log "installing cilium-cli ${CILIUM_CLI_VERSION}"
  local base="https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}" f="cilium-linux-${ARCH}.tar.gz"
  fetch "${base}/${f}" "$TMP/$f"
  verify "$TMP/$f" "$(curl -fsSL "${base}/${f}.sha256sum" | awk '{print $1}')"
  tar -C "$TMP" -xzf "$TMP/$f"
  install_bin "$TMP/cilium" cilium
  ok "cilium-cli ${CILIUM_CLI_VERSION}"
}

install_istioctl() {
  if version_ok istioctl "istioctl version --remote=false" "${ISTIO_VERSION}"; then ok "istioctl ${ISTIO_VERSION}"; return; fi
  log "installing istioctl ${ISTIO_VERSION}"
  local base="https://github.com/istio/istio/releases/download/${ISTIO_VERSION}" f="istio-${ISTIO_VERSION}-linux-${ARCH}.tar.gz"
  fetch "${base}/${f}" "$TMP/$f"
  verify "$TMP/$f" "$(curl -fsSL "${base}/${f}.sha256" | awk '{print $1}')"
  tar -C "$TMP" -xzf "$TMP/$f"
  install_bin "$TMP/istio-${ISTIO_VERSION}/bin/istioctl" istioctl
  ok "istioctl ${ISTIO_VERSION}"
}

install_calicoctl() {
  if version_ok calicoctl "calicoctl version --client 2>&1 || calicoctl version 2>&1" "${CALICO_VERSION}"; then ok "calicoctl ${CALICO_VERSION}"; return; fi
  log "installing calicoctl ${CALICO_VERSION}"
  local base="https://github.com/projectcalico/calico/releases/download/${CALICO_VERSION}" f="calicoctl-linux-${ARCH}"
  fetch "${base}/${f}" "$TMP/$f"
  verify "$TMP/$f" "$(sum_from_list "${base}/SHA256SUMS" "$f")"
  install_bin "$TMP/$f" calicoctl
  ok "calicoctl ${CALICO_VERSION}"
}

# --- kernel modules and sysctls -------------------------------------------
load_modules() {
  local mods=(geneve wireguard tun udp_tunnel ip6_udp_tunnel nf_tables sch_ingress cls_bpf)
  for m in "${mods[@]}"; do
    if ! lsmod | awk '{print $1}' | grep -qx "$m"; then
      $SUDO modprobe "$m" 2>/dev/null || {
        # Built-in modules do not show in lsmod; that is fine.
        grep -qw "${m}.ko" "/lib/modules/$(uname -r)/modules.builtin" 2>/dev/null || die "cannot load kernel module $m"
      }
    fi
  done
  printf '%s\n' "${mods[@]}" | $SUDO tee /etc/modules-load.d/ratatoskr.conf >/dev/null
  ok "kernel modules: ${mods[*]}"

  # k3d runs several kubelets on one kernel; the default inotify limits are too low.
  $SUDO tee /etc/sysctl.d/90-ratatoskr-k3d.conf >/dev/null <<'EOF'
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 1048576
EOF
  $SUDO sysctl -q --system >/dev/null
  ok "sysctls"
}

check_docker() {
  command -v docker >/dev/null || die "docker not installed"
  if ! docker info >/dev/null 2>&1; then
    if id -nG "$USER" | grep -qw docker; then
      die "docker daemon not reachable (is it running? 'systemctl status docker')"
    fi
    die "docker not accessible for $USER: run 'sudo usermod -aG docker $USER' and re-login (or use 'sg docker')"
  fi
  ok "docker $(docker info --format '{{.ServerVersion}}')"
}

main() {
  check_kernel
  install_apt
  install_go
  install_golangci_lint
  if ((WITH_K8S_TOOLS)); then
    install_kubectl
    install_helm
    install_k3d
    install_cilium_cli
    install_istioctl
    install_calicoctl
  fi
  if ((WITH_KMOD)); then load_modules; fi
  if ((WITH_K8S_TOOLS)); then check_docker; fi
  ok "bootstrap complete"
}

main
