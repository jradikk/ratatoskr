# Ratatoskr design

Status: living document, M0 baseline (2026-10-29). API group and label prefix:
`ratatoskr.skaldhall.io`.

## 1. Problem and goals

Operators define named egress gateways (`EgressGateway`, e.g. `berlin`). Each
gateway is a set of pods whose outbound side is a VPN tunnel provided by a
pluggable *upstream* container (OpenVPN, WireGuard, AmneziaWG, IPsec, custom).
Workloads anywhere in the cluster opt in with the label
`ratatoskr.skaldhall.io/gateway: berlin`. Their traffic — all of it, or a subset
selected by an `EgressPolicy` — is steered through an in-cluster GENEVE tunnel to
a gateway replica and leaves through that replica's VPN. When the gateway or its
VPN is unavailable, steered traffic **fails closed**: it is dropped, never sent
via the node's normal egress.

Must work on any CNI (Cilium ± encryption, Calico, flannel, …), with Istio
sidecar, Istio ambient or no mesh, on AWS/GCP/Azure/vSphere (Talos, Ubuntu),
kernel ≥ 5.10, and with Pod Security Admission `restricted` workloads.

Non-goals for v1: FQDN rules (API leaves room), IPv6 (types and MTU math are
family-aware; nothing is programmed), multi-cluster gateways, ingress through
the gateway, Windows nodes.

## 2. Architecture overview

```
 client pod netns (labeled)                      gateway pod netns
 ┌──────────────────────────────┐                ┌───────────────────────────────────────┐
 │ app / envoy / ztunnel socket │                │  gateway container      upstream ctr  │
 │        │ route lookup        │                │                                       │
 │  ip rules ─► table N ─► rtk0 │  GENEVE/UDP    │  gnv0 (collect_md) ─► table 100 ─►    │
 │  (or tc-bpf on eth0 ─► gnv0) │ ─────────────► │  anti-spoof ─► kill switch ─► SNAT ─► │ upstream0 ─► VPN
 │        excluded ─► eth0      │ (opt. inside   │                                       │
 └──────────────────────────────┘  WireGuard)    └───────────────────────────────────────┘
        ▲ programmed by                                   ▲ rendered by
   init container (driver=init)                      controller (Deployment, Services,
   or agent DaemonSet (driver=agent)                 ConfigMaps, status, Events)
```

Components (all one Helm chart):

| Component | Kind | Privileges | Responsibility |
|---|---|---|---|
| controller | Deployment | none | Reconcile CRDs; render gateway Deployments/Services; compute per-pod steering config and exclusions; status conditions, Events |
| webhook | Deployment | none | Mutate labeled pods (init container, annotations, DNS); validate CRDs and gateway access |
| agent | DaemonSet | NET_ADMIN, SYS_ADMIN, BPF (host PID ns read) | Program pod netns (driver=agent); keep it in sync with gateway endpoints; mark readiness |
| gateway | container in gateway pod | NET_ADMIN (pod netns only) | GENEVE termination, anti-spoof, policy routing, SNAT, kill switch, DNS forwarder, WireGuard peer registration |
| upstream | container in gateway pod | NET_ADMIN, MKNOD (pod netns only) | Create `upstream0` per the plugin contract |
| init | init container in client pods | driver=init: NET_ADMIN; driver=agent: none | Program netns (MVP) or wait for the agent's readiness marker |

The **datapath library** (`pkg/datapath`) is shared by agent, init and gateway:
netlink (vishvananda/netlink), nftables (google/nftables), wgctrl, cilium/ebpf.
Nothing shells out to `ip`/`nft`/`wg` in production code.

## 3. API

### 3.1 EgressGateway (namespaced; operator namespace by default)

As specified in the build prompt (`replicas`, `encryption`, `affinity`,
`upstream{type,secretRef,image?}`, `dns.mode`, `failMode`,
`allowedNamespaces.namespaceSelector`, `exclusions{autoDetect,extraCIDRs,allowCloudMetadata}`,
`resources`, `nodeSelector`, `tolerations`). Additions/clarifications:

- `spec.upstream.image` — required for `type: custom`, optional override otherwise.
- `spec.id` is *not* user-settable. The controller allocates a stable gateway ID
  (1..2^24-1) stored in `status.gatewayID`; it is the GENEVE VNI and selects
  routing table numbers in client netns.
- `status` additionally reports `gatewayID`, `effectiveExclusions` (list of CIDRs
  with their source: `podCIDR`, `serviceCIDR`, `node`, `apiserver`, `dns`,
  `linkLocal`, `extra`), `mtu` (`geneveMTU`, `wireguardMTU`, `effectiveMTU`, `mss`,
  per-mode), `wireguard.publicKeys` (per endpoint) and `observedGeneration`.
- Conditions: `Ready`, `UpstreamHealthy`, `EndpointsAvailable`, `ConfigValid`,
  `ExclusionsResolved`.
- `failMode`: only `closed` in v1 (the field exists so `open` can be added later
  deliberately; the validator rejects anything else).

### 3.2 EgressPolicy (namespaced; workload namespace)

As specified: `gatewayRef`, `workloadSelector`, `mode: include|exclude`,
`rules[]{cidrs[], ports[]{protocol,port,endPort?}}`, `excludeCIDRs[]`. Room for
FQDNs is left by making each rule a struct (a future `fqdns: []` sibling of
`cidrs`). Semantics:

| No policy | `mode: include` | `mode: exclude` |
|---|---|---|
| steer everything not excluded | steer only traffic matching some rule | steer everything except traffic matching some rule |

`excludeCIDRs` and auto-exclusions always win over rules. A rule with `ports`
matches only that destination port/protocol within its CIDRs (or anywhere if
`cidrs` is empty). Overlapping policies (two `EgressPolicy` objects selecting the
same pod) are rejected: by the validating webhook at policy create/update time
when the overlap is detectable from existing pods, and on the pod at admission;
the controller additionally sets `Conflict=True` on both policies and emits an
Event if it observes an overlap that slipped through (e.g. a label change).

### 3.3 Workload contract

- `ratatoskr.skaldhall.io/gateway: <name>` (label) — opt in.
- `ratatoskr.skaldhall.io/gateway-namespace: <ns>` (label or annotation) — gateway
  namespace override; default is the operator namespace.
- `ratatoskr.skaldhall.io/datapath-ready` (annotation, written by agent/init) —
  `"true"` plus `ratatoskr.skaldhall.io/datapath-config-hash` for the programmed config.

## 4. Client datapath

Both implementations consume the same compiled `datapath.ClientConfig` (pod IP,
gateway ID, selected endpoint + standby list, compiled rule set, exclusions, MTU,
encryption, identity) produced by `pkg/policy` from CRDs. The controller and CRDs
do not know which datapath is in use.

### 4.1 Addressing on the tunnel

GENEVE as implemented by Linux carries Ethernet frames, so the inner frame needs
a destination MAC the gateway accepts. Every Ratatoskr tunnel device uses
**fixed, locally-administered MACs**: clients `02:52:54:4b:00:01`, gateways
`02:52:54:4b:00:02` (each pod netns is its own L2 island, so reuse is safe). The
client routes via the link-local next hop `169.254.64.1` with a permanent
neighbour entry pointing at the gateway MAC; the gateway installs a permanent
neighbour for each client pod IP pointing at the client MAC. No ARP crosses the
tunnel.

**Outer GENEVE addresses are always pod IPs** (client pod IP ↔ gateway pod IP) in
both encryption modes. In `wireguard` mode the client routes the gateway pod IP
`/32` through its WireGuard device (and the gateway routes each client pod IP
`/32` through `wg0`); WireGuard's own UDP is fwmarked and bypasses those routes.
This keeps gateway anti-spoofing identical in both modes (see §5.2).

### 4.2 `iproute` datapath

In the pod netns:

- `rtk0`: GENEVE, `id <gatewayID>`, `remote <selected endpoint pod IP>`,
  `dstport 6081`, MTU = computed GENEVE MTU, fixed MAC; neighbour
  `169.254.64.1 → gateway MAC (permanent)`.
- Routing table `N = 0x52540000 | (gatewayID & 0xffff)` (configurable base):
  `default via 169.254.64.1 dev rtk0 onlink` and `unreachable default metric 4294967295`
  so a missing tunnel route never falls through to `main` (fail-closed). When no
  endpoint is healthy the agent replaces the tunnel route with `prohibit default`
  so applications fail fast (ICMP admin-prohibited) instead of timing out.
- `ip rule`s (priorities from a reserved band, 10000–10999 by default):
  1. `fwmark <wg>/<mask> lookup main` (WireGuard bypass, encrypted mode),
  2. `fwmark <inbound>/<mask> lookup main` (replies to connections that entered
     via eth0 from non-excluded sources — see §4.5),
  3. `to <exclusion> lookup main` for every effective exclusion,
  4. policy rules: `to <cidr> lookup N` (CIDR-only include rules),
     `fwmark <steer>/<mask> lookup N` (port-qualified include rules),
     `to <cidr> lookup main` / `fwmark <bypass>/<mask> lookup main` (exclude mode),
  5. catch-all `lookup N` (no policy, or `mode: exclude`).
- nftables table `inet ratatoskr` (pod netns): `route` output chain that sets
  marks for port-qualified rules using sets of CIDRs and port ranges; MSS clamp
  (`tcp flags syn tcp option maxseg size set rt mtu` on `oifname rtk0`);
  inbound connmark (§4.5).
- sysctls (netns-scoped): `net.ipv4.conf.{all,rtk0}.rp_filter=2`.

### 4.3 `ebpf` datapath

- One `gnv0` GENEVE device in `external` (collect_md) mode in the pod netns.
- A tc (clsact) **egress** program on `eth0`, loaded with cilium/ebpf and pinned
  per netns. Maps: `exclude_v4` (LPM trie), `include_v4` (LPM trie, value =
  rule-set bitmap), `port_rules` (hash: rule-id/proto/port → verdict),
  `endpoints` (array: selected + standby gateway endpoints with health),
  `identity` (pod identity TLV bytes), `config` (mode, gateway ID, MACs), and a
  per-reason `stats` percpu array.
- On a steered packet: rewrite the inner Ethernet destination to the gateway MAC,
  `bpf_skb_set_tunnel_key` (remote = selected endpoint, VNI = gatewayID),
  `bpf_skb_set_tunnel_opt` (Ratatoskr TLV class, pod identity), `bpf_redirect`
  to `gnv0`. No healthy endpoint → `TC_ACT_SHOT` and count `no_endpoint`.
- Encapsulated output from `gnv0` re-enters `eth0` egress; gateway endpoints are
  always in the exclusion set, so it is not re-steered.
- Return traffic arrives on `gnv0` and is delivered locally (weak host model);
  `rp_filter` is loose as in §4.2. MSS clamping uses the same nft rule.
- Tests use `BPF_PROG_TEST_RUN` on crafted packets (§11).

### 4.4 Gateway endpoint selection

Replicas have different upstream exit IPs, so selection is **sticky per client
pod**: rendezvous (HRW) hashing of `(podUID, endpointPodIP)` over healthy
endpoints. Removing or failing one endpoint only moves the pods that were on it;
adding one moves ~1/n of pods. Re-hashing moves flows to a different exit IP and
therefore breaks established connections — documented, not hidden. The selection
function lives in `pkg/datapath/affinity` and is used identically by both
datapaths. `affinity: per-pod` is the only v1 value.

### 4.5 Coexistence details

- **Istio sidecar**: steering is in routing, so Envoy's upstream sockets (pod IP
  source, original destination) follow the same `ip rule`s. Istio's own marks
  (`0x539`, `0xfff` masks) do not overlap Ratatoskr's mask (default
  `0x00f00000`). Kernel-generated GENEVE/WireGuard UDP is not TCP and is not
  redirected by Istio's iptables. Our wait-init container is placed first so
  native-sidecar `istio-proxy` starts after the datapath is ready.
- **Istio ambient**: ztunnel's in-pod sockets live in the pod netns and use the
  same routing table. HBONE traffic to other pods/waypoints targets pod/service
  CIDRs, which are always excluded.
- **Inbound from non-excluded sources** (e.g. `externalTrafficPolicy: Local`
  LoadBalancers preserving client IPs): replies must not be steered into the
  tunnel. nft marks connections that enter on `eth0` (`ct state new iif eth0 →
  ct mark |= inbound`) and restores the mark on output; rule 2 routes them via
  `main`. (Spec issue S8.)
- **CNI encryption** (Cilium WireGuard/IPsec): orthogonal — our UDP rides the CNI
  like any pod-to-pod traffic.

## 5. Gateway datapath

### 5.1 Forwarding

- `gnv0`: GENEVE `external` (collect_md), fixed gateway MAC, listening on 6081.
- `ip rule iif gnv0 lookup 100`; table 100: `default dev upstream0` +
  `unreachable default metric 4294967295`.
- `ip rule iif upstream0 lookup 101`; table 101: per client pod
  `<podIP>/32 encap ip id <gatewayID> dst <podIP> dev gnv0` + permanent
  neighbour `<podIP> → client MAC`. Programmed from the informer of selected pods.
- nftables `inet ratatoskr-gw`: `postrouting oifname upstream0 masquerade`;
  forward policy **drop** with accepts only for `iifname gnv0 oifname upstream0`
  and `iifname upstream0 oifname gnv0 ct state established,related`
  (kill switch); MSS clamp on both directions to the upstream path MTU.
- The pod's own default route stays on `eth0`; only forwarded traffic uses
  `upstream0`. The upstream plugin is forbidden to touch routes/DNS (§6).

### 5.2 Anti-spoofing (mandatory)

GENEVE is plain UDP reachable from any pod. Before forwarding, the gateway
requires **outer source IP == inner source IP == a pod currently selected for
this gateway** (from the informer cache):

- `iproute`: tc ingress on `gnv0` with one `flower enc_src_ip P src_ip P action ok`
  filter per allowed pod and a final `drop` (flower hashes on the mask, so lookup
  is O(1) in the number of pods).
- `ebpf`: tc ingress program on `gnv0` using `bpf_skb_get_tunnel_key` and a hash
  map of allowed pod IPs.
- `wireguard` mode: outer addresses are still pod IPs (§4.1) and WireGuard binds
  each peer's allowed-IP to the registered pod IP, so the same check applies;
  additionally, nft drops UDP 6081 arriving on `eth0` (GENEVE must arrive via
  `wg0`).
- TLVs are informational (flow logs, metrics) unless the packet came via an
  authenticated WireGuard peer.

Drops are counted per reason (`spoof`, `not_selected`, `kill_switch`,
`no_upstream`).

### 5.3 Health and readiness

The gateway container polls the upstream `GET /healthz` and `GET /info`. While
unhealthy it (1) fails its readiness probe so the controller removes it from
`status.endpoints` (clients re-hash or go to `prohibit`) and (2) keeps the
kill-switch and `unreachable` routes so in-flight steered packets are dropped.

## 6. Upstream plugin contract

An upstream is one container image run as the `upstream` container in the gateway
pod (shared netns). It MUST:

1. create a point-to-point/L3 interface named `upstream0`;
2. serve `GET /healthz` (200 when the tunnel is up and a probe through
   `upstream0` succeeds recently) and `GET /info` (JSON: `exitIP`, `mtu`,
   `handshakeAge`, `details`) on `127.0.0.1:9901`;
3. never change the pod's default route, other routes outside table 100, or
   `/etc/resolv.conf`; pushed `redirect-gateway`/DNS options are ignored;
4. read its configuration from the Secret mounted at `/etc/ratatoskr/upstream`
   (all keys of `spec.upstream.secretRef`).

`/dev/net/tun`: the plugin creates the node itself (`mknod /dev/net/tun c 10 200`)
using `CAP_MKNOD`; the container runtimes we target (containerd, CRI-O) allow
`c 10:200 rwm` in their default device cgroup. Fallback value
`gateway.tunDevice: hostPath` mounts the host's char device instead. See
ADR-0007.

### OpenVPN plugin

Secret keys: `client.ovpn` (required), `auth.txt` (optional), plus any files the
config references (CA, cert, key, tls-auth…). The sanitizer (`pkg/upstream/openvpn`)
parses the config, **removes** `redirect-gateway`, `dhcp-option`, `up`, `down`,
`route-up`, `ipchange`, `script-security`, `dev`, `dev-type`, `daemon`, `log*`,
`management*`, `plugin`, rewrites `auth-user-pass` to the mounted `auth.txt`,
rejects file references that escape the Secret directory, and starts OpenVPN with
`--dev upstream0 --dev-type tun --route-nopull --pull-filter ignore redirect-gateway
--pull-filter ignore dhcp-option --script-security 1`. Health = `upstream0` up +
periodic HTTP probe through `upstream0` (socket bound with `SO_BINDTODEVICE`);
prolonged failure restarts OpenVPN with exponential backoff.

## 7. WireGuard encryption mode

- Client key pair generated in the pod netns by the agent/init; the private key
  is held only in the kernel device (and the agent's memory for re-programming;
  never written to the API).
- Registration: `POST https://<gateway-pod-ip>:9443/v1/peers` with
  `{publicKey}`; authenticated by a projected ServiceAccount token (audience
  `ratatoskr.skaldhall.io/gateway`, 10 min). The gateway validates via TokenReview,
  maps the token's pod-name/UID claims to the pod, checks the pod's gateway label
  and namespace admission (`allowedNamespaces`), then adds the peer with
  `allowed-ips <podIP>/32`. Agent mode: the agent registers on the pod's behalf
  using a token requested via TokenRequest for the pod's ServiceAccount
  (`serviceaccounts/token` create permission bound to pod name).
- Gateway public keys and WireGuard ports are published in
  `EgressGateway.status.endpoints[].wireguardPublicKey`.
- Peers are removed when the pod disappears (informer) and by TTL (default 24h,
  refreshed by re-registration) as a backstop.

## 8. DNS

- `cluster` (default): unchanged pod DNS. Queries leave via the cluster's normal
  egress (document as a leak vector for privacy-sensitive users).
- `gateway`: webhook sets `dnsPolicy: None`, `dnsConfig.nameservers=[<gateway DNS
  Service ClusterIP>]`, searches `<ns>.svc.<clusterDomain> svc.<clusterDomain>
  <clusterDomain>`, `ndots:5`. The gateway forwarder sends `<clusterDomain>` and
  reverse zones of cluster CIDRs to kube-dns and everything else to upstream
  resolvers via `upstream0` (sockets marked into table 100). Service CIDRs are
  excluded, so DNS reaches the gateway over the cluster network.

## 9. Exclusions

Effective set = auto-detected ∪ `extraCIDRs` ∪ chart-level extras:

| Source | Detection |
|---|---|
| pod CIDRs | `Node.spec.podCIDRs` union; chart override for CNIs that ignore it (Cilium cluster-pool, Calico IPAM) — plus Calico/Cilium IPPool CRDs read if present, no API dependency |
| service CIDRs | `networking.k8s.io/v1 ServiceCIDR` when served, else chart value; refuse to mark Ready if unknown |
| node IPs | `Node.status.addresses` |
| API server | `default/kubernetes` EndpointSlices |
| kube-dns | ClusterIP + endpoints |
| gateway endpoints | always (pod IPs) |
| link-local | `169.254.0.0/16` |

`allowCloudMetadata: false` (default): `169.254.169.254/32` is installed as a
**`prohibit`** route in labeled pods (neither steered nor reachable); `true`:
reachable via the normal path. (Spec issue S9.) The effective set is reported in
status.

## 10. MTU

`pkg/mtu` (implemented in M0): GENEVE overhead = outer IP + UDP 8 + GENEVE 8 +
TLVs + inner Ethernet 14 (50 B over IPv4 without TLVs); WireGuard overhead = outer
IP + UDP 8 + 32. Effective MTU = min(GENEVE MTU, upstream0 MTU); MSS = MTU − 40.
Refuse below 576; warn below 1280. Computed values are set on `rtk0`/`gnv0`/`wg*`,
clamped via nft, and exposed in status.

## 11. Security model

- Privileged pieces: agent (enters other pods' netns; loads BPF), gateway and
  upstream containers (NET_ADMIN in their own netns only). Controller and webhook
  run unprivileged with least-privilege RBAC.
- Validating webhook + shipped ValidatingAdmissionPolicy: pods may use a gateway
  only if their namespace matches `allowedNamespaces` (defence in depth; the VAP
  works even if the webhook is down; the webhook is `failurePolicy: Fail` for
  labeled pods only via `objectSelector`).
- NetworkPolicies allow UDP 6081 and the WireGuard port only to gateway pods.
- Secrets: upstream Secrets are mounted only into the upstream container.
- Images: distroless/static, multi-arch, cosign keyless signing, SBOM + provenance.

## 12. Observability

Prometheus metrics (per gateway, per workload): bytes/packets/flows, drops by
reason, upstream health and handshake age, peer count, programming latency.
JSON logs (`log/slog`). Optional flow logs as OCSF Network Activity (`class_uid
4001`) with workload identity. CRD conditions and Events for every failure path.

## 13. Kernel and platform checks

Agent and gateway refuse to start (Event + condition) if kernel < 5.10 or if
GENEVE/WireGuard (when needed)/clsact are unavailable, probing by creating and
deleting throwaway devices in their own netns.

## 14. Testing

- Unit: controller logic, policy compilation, exclusion detection, MTU math,
  OpenVPN sanitizer, affinity hashing.
- Privileged (`-tags privileged`, run as root in CI): datapath programming in
  throwaway netns, nft rules, BPF `PROG_TEST_RUN`.
- CI e2e (`make e2e`): k3d + fake upstream (a "remote network" container
  reachable through a plain tunnel, echoing the caller's source IP).
- Live e2e (`make e2e-live`): OpenVPN + ipinfo.io, steps 1–13 of the spec.

## 15. Spec issues and resolutions

Recorded in [spec-issues.md](spec-issues.md).
