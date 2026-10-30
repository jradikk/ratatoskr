#!/usr/bin/env bash
# Sourced ONLY by the existing bounded final-gate run after setup. Never standalone.
# No provider data, tokens, logs, captures or real metadata service requests.

m8_metric() {
  local expected=$1 checkpoint=$2
  STAGE=$checkpoint
  observer_curl http://127.0.0.1:9902/metrics | awk -v want="$expected" \
    '$1=="ratatoskr_gateway_upstream_healthy" && $2==want {found=1} END {exit !found}'
  # Any HTTP response on PodIP is exposure, even non-200; require transport failure.
  if client curl --ipv4 --noproxy '*' --silent --connect-timeout 2 --max-time 3 \
      --output /dev/null "http://$GATEWAY_IP:9902/metrics" 2>/dev/null; then
    record "$checkpoint" failed 'Private metrics listener unexpectedly reachable over PodIP.'
    exit 1
  fi
  record "$checkpoint" passed "Loopback health gauge is $expected and PodIP:9902 is unreachable."
}

m8_measurements() {
  STAGE=m8-measured-mtu
  observer_curl http://127.0.0.1:9900/info | jq -e '
    .ready==true and .podMTU>=576 and .geneveMTU>=576 and .upstreamMTU>=576 and
    .geneveMTU<= (.podMTU-50) and
    .effectiveMTU==([.geneveMTU,.upstreamMTU]|min) and .mss==(.effectiveMTU-40)' >/dev/null
  record m8-measured-mtu passed 'Measured gateway MTUs agree with IPv4 carrier budget, effective minimum and MSS; PMTU/fragmentation still not covered.'
}

m8_apply_config() {
  timeout --signal=TERM --kill-after=5s 30s kubectl --context "$CTX" --request-timeout=10s \
    -n "$NAMESPACE" exec -i client -c tools -- sh -c \
    'umask 077; cat > /tmp/m8-client.json; exec /ratatoskr-init -config /tmp/m8-client.json' \
    < "$1" >/dev/null 2>&1
}

m8_make_config() {
  # Remove only remote /32 from cluster exclusions so both steered and ordinary
  # paths to the SAME reachable HTTP service can distinguish selector behavior.
  python3 "$ROOT/test/e2e/matrix/client-config.py" "$PRIVATE/client.json" "$REMOTE_IP" "$POD_CIDR" "$1" \
    > "$PRIVATE/m8-client.json"
}

m8_fake_selectors() {
  STAGE=m8-selective-policy
  for policy in include wrong-port wrong-cidr exclude; do
    m8_make_config "$policy"
    m8_apply_config "$PRIVATE/m8-client.json"
    expected=$CLIENT_IP
    [[ "$policy" != include ]] || expected=198.19.0.2
    client_curl "http://$REMOTE_IP:8080/echo" | jq -e --arg ip "$expected" '.ip==$ip' >/dev/null
    if [[ "$policy" == exclude ]]; then
      client_curl http://198.19.0.1:8080/echo | jq -e '.ip=="198.19.0.2"' >/dev/null
    fi
  done
  record m8-selective-policy passed 'Same reachable remote HTTP endpoint distinguishes include CIDR+TCP port, mismatching port/CIDR and exclude; CRD compiler/admission not covered.'
  STAGE=m8-no-endpoint
  m8_make_config no-endpoint
  m8_apply_config "$PRIVATE/m8-client.json"
  if client_curl "http://$REMOTE_IP:8080/echo" >/dev/null; then
    record m8-no-endpoint failed 'Selected reachable remote unexpectedly succeeded after endpoint withdrawal.'
    exit 1
  fi
  # Deliberately selected remote /32 is no longer a pod exclusion. Do not claim
  # its service VIP survives DNAT into that now-selected address on tc eBPF.
  client getent ahostsv4 kubernetes.default.svc.cluster.local >/dev/null
  api_code=$(client curl --ipv4 --noproxy '*' --silent --insecure --connect-timeout 3 --max-time 8 \
    --output /dev/null --write-out '%{http_code}' "https://$API_IP/version" 2>/dev/null)
  [[ "$api_code" == "$api_before" ]]
  m8_apply_config "$PRIVATE/client.json"
  client_curl "http://$REMOTE_IP:8080/echo" | jq -e --arg ip "$CLIENT_IP" '.ip==$ip' >/dev/null
  client_curl http://198.19.0.1:8080/echo | jq -e '.ip=="198.19.0.2"' >/dev/null
  record m8-no-endpoint passed 'Endpoint withdrawal blocks selected otherwise-reachable remote, preserves API/DNS; original full steering restored.'
}

m8_fake_payload() {
  STAGE=m8-payload-integrity
  # Remote fixture uses bytes.Repeat("ratatoskr", 512*1024): exactly 4.5 MiB.
  expected_sha=$(python3 - <<'PY'
import hashlib
print(hashlib.sha256(b"ratatoskr" * (512*1024)).hexdigest())
PY
)
  timeout --signal=TERM --kill-after=5s 70s kubectl --context "$CTX" --request-timeout=70s \
    -n "$NAMESPACE" exec client -c tools -- sh -c '
      set -eu; umask 077
      file=$(mktemp /tmp/m8-payload.XXXXXX)
      trap '\''rm -f "$file"'\'' EXIT
      curl --ipv4 --noproxy "*" --silent --fail --connect-timeout 5 --max-time 60 \
        --max-filesize 4718592 --output "$file" http://198.19.0.1:8080/payload 2>/dev/null
      test "$(wc -c < "$file")" -eq 4718592
      test "$(sha256sum "$file" | cut -d " " -f 1)" = "$1"
    ' sh "$expected_sha" >/dev/null 2>&1
  record m8-payload-integrity passed '4.5 MiB tunneled payload exact byte count and deterministic SHA256 matched; no payload/capture retained.'
}
