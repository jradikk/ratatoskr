#!/usr/bin/env bash
# Direct-config M1 proof with optional M8 subset. No registry push/build or host changes.
set +x
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE=fake
REPORT_DIR=
IMPORT=yes
SKIP=no
HAS_TOKEN=no
EXTENDED=no
DATAPATH_MODE=iproute
for arg in "$@"; do
  case "$arg" in
    --mode=fake|--mode=live) MODE=${arg#--mode=} ;;
    --no-build) : ;; # Builds are parent/operator-managed; all images are local.
    --no-import) IMPORT=no ;;
    --skip) SKIP=yes ;;
    --extended) EXTENDED=yes ;;
    --datapath=iproute|--datapath=ebpf) DATAPATH_MODE=${arg#--datapath=} ;;
    --report-dir=*) REPORT_DIR=${arg#--report-dir=} ;;
    *) printf '%s\n' 'unknown argument; see test/e2e/m1/README.md' >&2; exit 2 ;;
  esac
done
if [[ ( "$EXTENDED" == yes || "$DATAPATH_MODE" == ebpf ) && "${RATATOSKR_E2E_FINAL_GATE:-}" != 1 ]]; then
  printf '%s\n' 'Extended traffic execution deferred; final gate authorization required.' >&2
  exit 2
fi
for tool in jq python3 timeout; do
  command -v "$tool" >/dev/null || { printf 'missing local tool: %s\n' "$tool" >&2; exit 2; }
done
if [[ -z "$REPORT_DIR" ]]; then
  REPORT_DIR=$(mktemp -d "/tmp/ratatoskr-m1-${MODE}-report.XXXXXX")
fi
# Keep even non-secret evidence outside the repository/build context.
REPORT_DIR=$(python3 - "$REPORT_DIR" "$ROOT" <<'PY'
from pathlib import Path
import sys
p, root = (Path(x).resolve() for x in sys.argv[1:])
if p == root or root in p.parents:
    sys.exit("report directory must be outside the repository")
print(p)
PY
)
mkdir -p "$REPORT_DIR"
PRIVATE=$(mktemp -d /tmp/ratatoskr-m1-private.XXXXXX)
CTX=k3d-ratatoskr-flannel
NAMESPACE="ratatoskr-m1-${MODE}-$$"
CLUSTER_CREATED=no
NAMESPACE_CREATED=no
RESULT=failed
STAGE=setup
REPORT="$REPORT_DIR/report.json"
export NAMESPACE
export GATEWAY_IMAGE=${GATEWAY_IMAGE:-ghcr.io/skaldhall/ratatoskr-gateway:dev}
export TOOLS_IMAGE=${TOOLS_IMAGE:-ratatoskr-tools:m1-local}
export FAKE_IMAGE=${FAKE_IMAGE:-ratatoskr-fakeupstream:m1-local}
export OPENVPN_IMAGE=${OPENVPN_IMAGE:-ratatoskr-openvpn:m1-local}
POD_CIDR=${M1_POD_CIDR:-10.42.0.0/16}
SERVICE_CIDR=${M1_SERVICE_CIDR:-10.43.0.0/16}
jq -n --arg mode "$MODE" --arg namespace "$NAMESPACE" --arg datapath "$DATAPATH_MODE" --arg extended "$EXTENDED" \
  '{scope:"direct-config-subset-not-full-matrix",mode:$mode,datapath:$datapath,extended:$extended,namespace:$namespace,status:"running",checks:[],
    deferred:["All end-to-end executions are deferred to final project gate",
      "Full M2-M9 scenario coverage is not implemented by this scaffold"]}' > "$REPORT"

write_markdown() {
  jq -r '"# M1 manual proof\n\nStatus: **" + .status + "**\nMode: " + .mode +
    "\nDatapath: " + .datapath + "\nExtended M8 subset: " + .extended +
    "\nScope: direct-config subset only; not the full end-state matrix.\n\n## Checks\n" +
    ([.checks[] | "- [" + .status + "] " + .name + ": " + .detail] | join("\n")) +
    "\n\n## Deferred coverage\n" + ([.deferred[] | "- " + .] | join("\n")) + "\n"' \
    "$REPORT" > "$REPORT_DIR/report.md"
}
record() {
  jq --arg name "$1" --arg status "$2" --arg detail "$3" \
    '.checks += [{name:$name,status:$status,detail:$detail}]' "$REPORT" > "$PRIVATE/report.next"
  mv "$PRIVATE/report.next" "$REPORT"
  write_markdown
}
k() { kubectl --context "$CTX" --request-timeout=10s "$@"; }
wait_pods() {
  local seconds=$1
  shift
  # Watches need the full readiness budget, not k()'s short single-request limit.
  timeout --signal=TERM --kill-after=5s "$((seconds + 15))s" kubectl --context "$CTX" \
    --request-timeout="$((seconds + 5))s" -n "$NAMESPACE" wait "$@" --timeout="${seconds}s"
}
client() { timeout --signal=TERM --kill-after=5s 30s kubectl --context "$CTX" \
  --request-timeout=10s -n "$NAMESPACE" exec client -c tools -- "$@"; }
observer() { timeout --signal=TERM --kill-after=5s 30s kubectl --context "$CTX" \
  --request-timeout=10s -n "$NAMESPACE" exec gateway -c observer -- "$@"; }
client_curl() { client curl --ipv4 --noproxy '*' --silent --show-error --fail \
  --connect-timeout 3 --max-time 8 "$@" 2>/dev/null; }
observer_curl() { observer curl --ipv4 --noproxy '*' --silent --fail \
  --connect-timeout 3 --max-time 5 "$@" 2>/dev/null; }
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  set +e
  if (( code != 0 )); then
    RESULT=failed
    record "$STAGE" failed 'Command failed or timed out; no raw logs collected.'
  fi
  if [[ "$NAMESPACE_CREATED" == yes ]]; then
    if timeout --signal=TERM --kill-after=5s 130s kubectl --context "$CTX" \
        --request-timeout=125s delete namespace "$NAMESPACE" --wait=true --timeout=120s >/dev/null 2>&1; then
      record cleanup-namespace passed 'Ephemeral namespace and Secrets removed.'
    else
      RESULT=failed
      record cleanup-namespace failed 'Namespace cleanup timed out; remove namespace manually before another run.'
    fi
  fi
  if [[ "$CLUSTER_CREATED" == yes ]]; then
    if timeout --signal=TERM --kill-after=5s 90s bash "$ROOT/hack/k3d-down.sh" flannel >/dev/null 2>&1; then
      record cleanup-cluster passed 'Cluster created by this harness removed using hack lifecycle.'
    else
      RESULT=failed
      record cleanup-cluster failed 'Cluster cleanup failed; use hack/k3d-down.sh flannel before another variant.'
    fi
  fi
  jq --arg status "$RESULT" '.status=$status' "$REPORT" > "$PRIVATE/report.next"
  mv "$PRIVATE/report.next" "$REPORT"
  write_markdown
  rm -rf "$PRIVATE"
  printf 'M1 %s: %s\nReports: %s/report.{json,md}\n' "$MODE" "$RESULT" "$REPORT_DIR"
  case "$RESULT" in passed|skipped) exit 0 ;; inconclusive) exit 3 ;; *) exit 1 ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$SKIP" == yes ]]; then
  RESULT=skipped
  record execution skipped 'Explicit --skip; no cluster, Secret, or traffic probe created.'
  exit 0
fi
if [[ "$MODE" == live && -z "${RATATOSKR_E2E_OVPN:-}" ]]; then
  RESULT=skipped
  record live-input skipped 'RATATOSKR_E2E_OVPN is unset; no cluster, Secret, or external request created.'
  exit 0
fi
if [[ "$MODE" == live ]]; then
  STAGE=live-input
  # Never echo environment values or copy provider files into the repo.
  [[ -z "${IPINFO_TOKEN:-}" ]] || HAS_TOKEN=yes
  python3 "$ROOT/test/e2e/m1/bundle.py" "$ROOT" "$PRIVATE"
  # Only fixed private staged paths survive into kubectl/lifecycle commands.
  unset RATATOSKR_E2E_OVPN RATATOSKR_E2E_OVPN_AUTH \
    RATATOSKR_E2E_OVPN_CA RATATOSKR_E2E_OVPN_CERT RATATOSKR_E2E_OVPN_KEY
  python3 - "$ROOT" "$PRIVATE/token" <<'PY'
import os
import sys
country = os.environ.get("RATATOSKR_E2E_EXPECT_COUNTRY", "")
if country and (len(country) != 2 or not country.isascii() or not country.isupper() or not country.isalpha()):
    sys.exit("expected country must be a two-letter uppercase country code")
token = os.environ.get("IPINFO_TOKEN", "")
if token and (len(token) > 512 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in token)):
    sys.exit("invalid optional token format")
if token:
    fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
PY
  # Unrelated lifecycle/import processes must not inherit the literal token.
  unset IPINFO_TOKEN
fi
for tool in kubectl k3d; do
  command -v "$tool" >/dev/null || { record prerequisites failed "Missing local tool: $tool"; exit 1; }
done
[[ $(uname -s) == Linux ]] || { record prerequisites failed 'Linux validation VM required.'; exit 1; }
STAGE=cluster-preflight
# The mandatory lifecycle enforces one-cluster-at-a-time and checks resources on
# creation. Do not re-charge existing cluster RAM or bypass that preflight.
existing=$(k3d cluster list -o json)
if ! jq -e 'any(.[]; .name=="ratatoskr-flannel")' <<< "$existing" >/dev/null; then
  CLUSTER_CREATED=yes
fi
timeout --signal=TERM --kill-after=10s 660s bash "$ROOT/hack/k3d-up.sh" flannel --mesh=none > "$PRIVATE/lifecycle.log" 2>&1 || {
  # Lifecycle output contains no live data, but emit only a fixed failure summary.
  record cluster-preflight failed 'hack/k3d-up.sh failed (resource/module/tool prerequisites or cluster readiness); inspect lifecycle manually.'
  exit 1
}
record cluster-preflight passed 'Mandatory flannel lifecycle completed; no VM/host changes performed by harness.'
STAGE=node-topology
nodes=$(k get nodes -o json)
# One server and two agents; place gateway and selected client on different nodes.
REMOTE_NODE=$(jq -er '[.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] != null)] | if length==1 then .[0].metadata.name else error("topology") end' <<< "$nodes")
GATEWAY_NODE=$(jq -er '[.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] == null)] | sort_by(.metadata.name) | if length==2 then .[0].metadata.name else error("topology") end' <<< "$nodes")
CLIENT_NODE=$(jq -er '[.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] == null)] | sort_by(.metadata.name) | if length==2 then .[1].metadata.name else error("topology") end' <<< "$nodes")
export REMOTE_NODE GATEWAY_NODE CLIENT_NODE
# Validate the explicitly declared k3d CIDRs, including every node pod subnet.
python3 - "$POD_CIDR" "$SERVICE_CIDR" "$nodes" <<'PY'
import ipaddress
import json
import sys
pods, services = (ipaddress.IPv4Network(x) for x in sys.argv[1:3])
if pods.overlaps(services):
    sys.exit("declared pod and service CIDRs overlap")
for node in json.loads(sys.argv[3])["items"]:
    cidr = ipaddress.IPv4Network(node["spec"]["podCIDR"])
    if not cidr.subnet_of(pods):
        sys.exit("declared pod CIDR does not contain all node pod CIDRs")
PY
API_IP=$(k -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')
python3 - "$SERVICE_CIDR" "$API_IP" <<'PY'
import ipaddress
import sys
if ipaddress.IPv4Address(sys.argv[2]) not in ipaddress.IPv4Network(sys.argv[1]):
    sys.exit("declared service CIDR does not contain API ClusterIP")
PY
record node-topology passed 'One server/two agents; client and gateway use different agents; declared CIDRs validated.'
if [[ "$IMPORT" == yes ]]; then
  STAGE=local-image-import
  images=("$GATEWAY_IMAGE" "$TOOLS_IMAGE" "$FAKE_IMAGE")
  [[ "$MODE" != live ]] || images+=("$OPENVPN_IMAGE")
  timeout --signal=TERM --kill-after=5s 120s k3d image import --cluster ratatoskr-flannel "${images[@]}" >/dev/null 2>&1 || {
    record local-image-import failed 'Local image import failed; parent/operator must build images first. No registry fallback.'; exit 1;
  }
fi
STAGE=namespace
if k get namespace "$NAMESPACE" >/dev/null 2>&1; then
  record namespace failed 'Generated namespace already exists; refusing to overwrite or remove it.'
  exit 1
fi
python3 "$ROOT/test/e2e/m1/render.py" "$ROOT/test/e2e/m1/templates/namespace.yaml.tmpl" > "$PRIVATE/namespace.yaml"
NAMESPACE_CREATED=yes
k apply -f "$PRIVATE/namespace.yaml" >/dev/null
if [[ "$MODE" == live ]]; then
  STAGE=secret-creation
  secret_args=("--from-file=client.ovpn=$PRIVATE/upstream/client.ovpn")
  for key in auth.txt ca.crt client.crt client.key; do
    [[ ! -f "$PRIVATE/upstream/$key" ]] || secret_args+=("--from-file=$key=$PRIVATE/upstream/$key")
  done
  # kubectl writes complete Secret YAML only into a private out-of-repo directory.
  k -n "$NAMESPACE" create secret generic m1-upstream "${secret_args[@]}" \
    --dry-run=client -o yaml > "$PRIVATE/upstream-secret.yaml" 2>/dev/null
  k create -f "$PRIVATE/upstream-secret.yaml" >/dev/null 2>&1
  rm -f "$PRIVATE/upstream-secret.yaml"
  rm -rf "$PRIVATE/upstream"
  if [[ "$HAS_TOKEN" == yes ]]; then
    k -n "$NAMESPACE" create secret generic m1-ipinfo --from-file="token=$PRIVATE/token" \
      --dry-run=client -o yaml > "$PRIVATE/ipinfo-secret.yaml" 2>/dev/null
    k create -f "$PRIVATE/ipinfo-secret.yaml" >/dev/null 2>&1
    rm -f "$PRIVATE/token" "$PRIVATE/ipinfo-secret.yaml"
  fi
  unset IPINFO_TOKEN RATATOSKR_E2E_OVPN RATATOSKR_E2E_OVPN_AUTH \
    RATATOSKR_E2E_OVPN_CA RATATOSKR_E2E_OVPN_CERT RATATOSKR_E2E_OVPN_KEY
  record secret-creation passed 'Upstream and optional token Secrets created from files; no credential output retained.'
fi
STAGE=baseline-pods
base=base.yaml.tmpl
[[ "$MODE" != live ]] || base=base-live.yaml.tmpl
[[ "$DATAPATH_MODE" != ebpf ]] || base=${base%.yaml.tmpl}-ebpf.yaml.tmpl
python3 "$ROOT/test/e2e/m1/render.py" "$ROOT/test/e2e/m1/templates/$base" > "$PRIVATE/base.yaml"
k apply -f "$PRIVATE/base.yaml" >/dev/null
wait_pods 120 --for=condition=Ready pod/remote pod/client >/dev/null
REMOTE_IP=$(k -n "$NAMESPACE" get pod remote -o jsonpath='{.status.podIP}')
CLIENT_IP=$(k -n "$NAMESPACE" get pod client -o jsonpath='{.status.podIP}')
ORDINARY_IP=$(k -n "$NAMESPACE" get service ordinary -o jsonpath='{.spec.clusterIP}')
export REMOTE_IP CLIENT_IP
baseline=$(client_curl "http://$REMOTE_IP:8080/echo")
jq -e --arg ip "$CLIENT_IP" '.ip==$ip' <<< "$baseline" >/dev/null
client cat /etc/resolv.conf > "$PRIVATE/resolv.before"
client getent ahostsv4 kubernetes.default.svc.cluster.local >/dev/null
api_before=$(client curl --ipv4 --noproxy '*' --silent --insecure --connect-timeout 3 --max-time 8 \
  --output /dev/null --write-out '%{http_code}' "https://$API_IP/version" 2>/dev/null)
[[ "$api_before" != 000 ]]
# A ready endpoint can precede kube-proxy's Service VIP programming. Give the
# ordinary path a bounded convergence window; never accept a wrong source IP.
service_deadline=$((SECONDS + 45))
while true; do
  ordinary_response=$(client_curl "http://$ORDINARY_IP:8080/echo") || ordinary_response=
  if jq -e --arg ip "$CLIENT_IP" '.ip==$ip' <<< "$ordinary_response" >/dev/null 2>&1; then
    break
  fi
  (( SECONDS < service_deadline )) || { record direct-baseline failed 'Ordinary ClusterIP did not preserve client PodIP within 45 seconds.'; exit 1; }
  sleep 2
done
record direct-baseline passed 'Remote PodIP sees selected client PodIP on ordinary cluster path; DNS, API TCP/TLS and ClusterIP reachable.'
STAGE=gateway-startup
gateway_template=gateway-$MODE.yaml.tmpl
[[ "$DATAPATH_MODE" != ebpf ]] || gateway_template=${gateway_template%.yaml.tmpl}-ebpf.yaml.tmpl
python3 "$ROOT/test/e2e/m1/render.py" "$ROOT/test/e2e/m1/templates/$gateway_template" > "$PRIVATE/gateway.yaml"
k apply -f "$PRIVATE/gateway.yaml" >/dev/null
wait_pods 180 --for=condition=Ready pod/gateway >/dev/null
GATEWAY_IP=$(k -n "$NAMESPACE" get pod gateway -o jsonpath='{.status.podIP}')
observer ip -j -4 route show table main | jq -e '[.[] | select(.dst=="default")] | length>0 and all(.[]; .dev=="eth0")' >/dev/null
info=$(observer_curl http://127.0.0.1:9900/info)
jq -e '.ready==true' <<< "$info" >/dev/null
EXIT_IP=$(jq -er '.exitIP | select(type=="string" and length>0)' <<< "$info")
record gateway-ready passed 'Gateway is Ready; cached /info exposes exitIP; gateway main default remains on eth0.'
STAGE=client-steering
jq -n --arg pod "$CLIENT_IP" --arg endpoint "$GATEWAY_IP" --arg pods "$POD_CIDR" --arg svc "$SERVICE_CIDR" \
  '{podIP:$pod,gatewayID:7,endpoint:$endpoint,mtu:1400,
    exclusions:[$pods,$svc,($endpoint+"/32")],encryption:"none"}' > "$PRIVATE/client.json"
timeout --signal=TERM --kill-after=5s 30s kubectl --context "$CTX" --request-timeout=10s \
  -n "$NAMESPACE" exec -i client -c tools -- sh -c \
  'umask 077; cat > /tmp/client.json; exec /ratatoskr-init -config /tmp/client.json' < "$PRIVATE/client.json" >/dev/null 2>&1
record client-steering passed "Client init executed in selected pod netns using $DATAPATH_MODE and explicit cluster exclusions; no workload netns switching."
STAGE=cluster-preservation
client cat /etc/resolv.conf > "$PRIVATE/resolv.after"
cmp "$PRIVATE/resolv.before" "$PRIVATE/resolv.after"
client getent ahostsv4 kubernetes.default.svc.cluster.local >/dev/null
api_after=$(client curl --ipv4 --noproxy '*' --silent --insecure --connect-timeout 3 --max-time 8 \
  --output /dev/null --write-out '%{http_code}' "https://$API_IP/version" 2>/dev/null)
[[ "$api_after" == "$api_before" ]]
client_curl "http://$ORDINARY_IP:8080/echo" | jq -e --arg ip "$CLIENT_IP" '.ip==$ip' >/dev/null
client_curl "http://$REMOTE_IP:8080/echo" | jq -e --arg ip "$CLIENT_IP" '.ip==$ip' >/dev/null
record cluster-preservation passed 'DNS resolver unchanged; DNS lookup, API response and ordinary PodIP/ClusterIP paths preserved after steering.'
if [[ "$EXTENDED" == yes ]]; then
  # shellcheck source=test/e2e/m1/extended.sh
  source "$ROOT/test/e2e/m1/extended.sh"
  m8_measurements
  m8_metric 1 m8-private-metric-ready
fi
if [[ "$MODE" == fake ]]; then
  STAGE=fake-tunnel-echo
  [[ "$EXIT_IP" == 198.19.0.2 ]]
  client_curl http://198.19.0.1:8080/echo | jq -e '.ip=="198.19.0.2"' >/dev/null
  record fake-tunnel-echo passed 'Steered request reports fake upstream inner source 198.19.0.2, not ordinary client/outer PodIP.'
  if [[ "$EXTENDED" == yes ]]; then
    m8_fake_payload
    m8_fake_selectors
  fi
  STAGE=fake-fail-close
  timeout --signal=TERM --kill-after=5s 30s kubectl --context "$CTX" --request-timeout=10s \
    -n "$NAMESPACE" exec gateway -c upstream -- /fakeupstream -role down >/dev/null 2>&1
  deadline=$((SECONDS + 60))
  while true; do
    code=$(observer curl --ipv4 --noproxy '*' --silent --connect-timeout 3 --max-time 5 \
      --output /dev/null --write-out '%{http_code}' http://127.0.0.1:9900/healthz 2>/dev/null) || code=000
    [[ "$code" != 503 ]] || break
    (( SECONDS < deadline )) || { record fake-fail-close failed 'Gateway did not return unhealthy HTTP 503 within 60 seconds.'; exit 1; }
    sleep 2
  done
  observer_curl http://127.0.0.1:9900/info | jq -e '.ready==false' >/dev/null
  wait_pods 30 --for=condition=Ready=false pod/gateway >/dev/null
  if [[ "$EXTENDED" == yes ]]; then
    m8_metric 0 m8-private-metric-down
  fi
  STAGE=fake-fail-close
  if client_curl http://198.19.0.1:8080/echo >/dev/null; then
    record fake-fail-close failed 'Steered request unexpectedly succeeded with upstream down.'; exit 1
  fi
  client_curl "http://$REMOTE_IP:8080/echo" | jq -e --arg ip "$CLIENT_IP" '.ip==$ip' >/dev/null
  client_curl "http://$ORDINARY_IP:8080/echo" | jq -e --arg ip "$CLIENT_IP" '.ip==$ip' >/dev/null
  record fake-fail-close passed 'Upstream link down -> gateway NotReady and steered request fails; ordinary PodIP/ClusterIP requests still succeed.'
  STAGE=fake-recovery
  timeout --signal=TERM --kill-after=5s 30s kubectl --context "$CTX" --request-timeout=10s \
    -n "$NAMESPACE" exec gateway -c upstream -- /fakeupstream -role up >/dev/null 2>&1
  wait_pods 90 --for=condition=Ready pod/gateway >/dev/null
  client_curl http://198.19.0.1:8080/echo | jq -e '.ip=="198.19.0.2"' >/dev/null
  record fake-recovery passed 'Upstream link restored; readiness and steered request recovered.'
  if [[ "$EXTENDED" == yes ]]; then
    m8_metric 1 m8-private-metric-recovered
  fi
else
  STAGE=live-exit-check
  # At most two harness ipinfo calls, with one 10s backoff on HTTP 429.
  observed=$(timeout --signal=TERM --kill-after=5s 50s kubectl --context "$CTX" \
    --request-timeout=10s -n "$NAMESPACE" exec -i client -c tools -- sh -s \
    < "$ROOT/test/e2e/m1/ipinfo.sh" 2>/dev/null)
  if [[ $(jq -er .status <<< "$observed") == inconclusive ]]; then
    RESULT=inconclusive
    record live-exit-check inconclusive 'External IP service unavailable, malformed or rate-limited; no success claimed.'
    exit 0
  fi
  jq -e --arg exit "$EXIT_IP" '.ip==$exit' <<< "$observed" >/dev/null
  if [[ -n "${RATATOSKR_E2E_EXPECT_COUNTRY:-}" ]]; then
    jq -e --arg country "$RATATOSKR_E2E_EXPECT_COUNTRY" '.country==$country' <<< "$observed" >/dev/null
  fi
  record live-exit-check passed 'Selected client public exit matches gateway cached exitIP; optional expected country matched.'
  record live-failure-injection skipped 'Live upstream disruption/recovery is not automated by this M1 scaffold.'
fi
# A successful direct-config smoke check must not overwrite a deliberately
# inconclusive extended selector checkpoint. The matrix remains non-green and
# can continue with the next independent cell (runner exit 3).
if jq -e 'any(.checks[]; .status=="inconclusive")' "$REPORT" >/dev/null; then
  RESULT=inconclusive
else
  RESULT=passed
fi
exit 0
