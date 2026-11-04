# Ratatoskr Helm chart

Ratatoskr provides label-driven Kubernetes egress gateways. This chart installs
the controller, validating and mutating admission webhooks, node agent (when
enabled), ServiceAccounts and scoped RBAC. It **does not** render gateway Pods:
the controller manages gateway Deployments, Services, ConfigMaps and ingress
policies in the namespaces of their EgressGateway objects.
The deployable upstream type is currently **OpenVPN only**. API fields for
custom and other upstream types do not imply a runnable controller/plugin;
unsupported configurations fail closed rather than falling back to direct
egress.

## Install

Requires Kubernetes 1.29+, Linux nodes supporting GENEVE/TUN and the requested
datapath, and an upstream configuration Secret created separately in each
gateway namespace. Verify the six component images (`controller`, `webhook`,
`agent`, `gateway`, `init`, `upstream-openvpn`) exist at the configured registry
and tag before installing. Do not put VPN profiles, keys or credentials in
Helm values or chart files.

Create a values file with your actual Service CIDRs and CRI socket path, then
install a published version:

```sh
helm upgrade --install ratatoskr oci://ghcr.io/jradikk/charts/ratatoskr \
  --version 0.1.0 --values ratatoskr-values.yaml \
  --namespace ratatoskr-system --create-namespace --wait --timeout 5m
```

The [project quickstart](../../README.md#install-with-helm) walks through the
values file, VPN Secret, gateway, namespace authorization, and workload setup.
For an offline/mirrored chart, substitute its archive or local chart directory
for the OCI reference. Use a version available in the registry.

The default image registry is `ghcr.io/jradikk`; the default tag is the chart
`appVersion` (`0.1.0`). Use `image.registry`, `image.tag` and
`image.pullPolicy` if your verified images are mirrored or locally imported.
`operatorNamespace`, if set, must equal the Helm release namespace. Once ready,
create an EgressGateway and label eligible workload Pods
`ratatoskr.skaldhall.io/gateway=<gateway-name>`; namespace authorization and
policy selection are enforced by admission. The controller and webhook serve
`/healthz` and `/readyz` on 8081; admission uses HTTPS 9443 behind the
`ratatoskr-webhook` Service on 443.

## Configuration

| Value | Default | Purpose |
|---|---|---|
| `driver` | `agent` | `agent` runs one node-local DaemonSet; `init` programs each opted-in Pod using a NET_ADMIN init container. |
| `datapath` | `iproute` | `iproute` or opt-in `ebpf`; eBPF needs supported kernel/seccomp/BPF capability policy. eBPF plus WireGuard is not supported. |
| `agent.healthPort` | `19903` | Agent Pod-network health/readiness port; set a different port if required by cluster policy. |
| `agent.criSocket` | `/run/containerd/containerd.sock` | Node CRI Unix socket; on k3s/k3d use `/run/k3s/containerd/containerd.sock`. |
| `clusterDomain` | `cluster.local` | Kubernetes DNS domain for webhook certificates and gateway DNS. |
| `dns.clusterIP` | empty | Optional literal cluster DNS IPv4 (Service VIP or reachable NodeLocal resolver). Empty uses the controller Pod's ClusterFirst `/etc/resolv.conf` nameserver. Gateway DNS no longer requires a `kube-system/kube-dns` Service. Rejects loopback, multicast, unspecified or invalid addresses. |
| `dns.upstreamIP` | `1.1.1.1` | Gateway-mode upstream resolver, accessible over the VPN. |
| `dns.upstreamProbeURL` | empty | Optional operator-only tunnel-bound literal IPv4 HTTP(S) exit probe; leave empty for the plugin default. No credentials in URL. |
| `exclusions.serviceCIDRs`, `exclusions.podCIDRs`, `exclusions.extraCIDRs` | `[]` | Direct-network ranges; confirm cluster Pod/Service ranges before steering traffic. If discovery cannot establish them, Gateway Ready=False and the `ExclusionDiscoveryFailed` condition/Event identifies the safe remediation category. Missing Pod CIDRs require `exclusions.podCIDRs` or Node.spec.podCIDRs; missing Service CIDRs require `exclusions.serviceCIDRs` or the ServiceCIDR API. ReadDenied means check controller permissions; ReadFailed means check API availability. Raw API errors and CIDR values are not published. |
| `controller.replicas`, `webhook.replicas` | `1`, `1` | Controller replicas >1 require `controller.leaderElection.enabled=true`. |
| `networkPolicy.enabled` | `true` | Install component-specific ingress-only policies: controller 8081, webhook 9443/8081, agent `agent.healthPort` in agent mode. |

Agent-mode workload wait-init is unprivileged and has no workload API token;
its readiness depends on the node agent's applied gateway-configuration
acknowledgement. Init-mode clients connect to **gateway Pod IPs**, not the
Gateway Service VIP. After endpoint IP changes, affected init workloads need
a controlled rollout to reprogram their routes. The controller surfaces a
`ClientRestartRequired` condition; agent-mode endpoints can reconcile in
place. Use EgressGateway status and conditions, not Service VIP health, to
judge endpoint readiness.

## Independent upstream profiles

A Gateway can name up to eight independently credentialed OpenVPN exits instead
of using legacy `upstream.secretRef`. Each profile has one controller-owned
Deployment and one upstream Pod; each Pod mounts **only its own** Secret, while
the Gateway shares an owner-controlled client-routing ConfigMap. Profiles must
have distinct lowercase DNS-label names, valid Secret names in the Gateway
namespace, and `spec.replicas: 1` (one Pod per profile). Do not set both
`upstream.profiles` and `upstream.secretRef`. A profile removal retires only the
Deployment owned by that Gateway UID; the selected endpoint may move, which
can break established connections when exit identities differ.

```yaml
apiVersion: ratatoskr.skaldhall.io/v1alpha1
kind: EgressGateway
metadata:
  name: exits
  namespace: ratatoskr-system
spec:
  replicas: 1
  upstream:
    type: openvpn
    profiles:
      - name: berlin
        secretRef:
          name: vpn-berlin
      - name: oslo
        secretRef:
          name: vpn-oslo
  allowedNamespaces:
    namespaceSelector:
      matchLabels:
        egress: enabled
```

Do not put provider credentials in this object. Gateway status lists the
independently healthy PodIP endpoints and their applied-config hashes; it does
not disclose Secret contents. This is per-Pod endpoint affinity, not a promise
of per-flow load balancing or identical external exit IPs.

## Security and operations

The agent runs as root with hostPID and a separate Pod network namespace
(`hostNetwork: false`), NET_ADMIN/SYS_ADMIN (plus BPF/PERFMON for eBPF), read-only node CRI socket and `/var/run/netns` mount,
with no host network namespace bind mount,
and a cluster-wide token-request permission for short-lived bound registration.
**Treat the agent as node-root-equivalent** and restrict its placement and
ability to modify its ServiceAccount. In agent mode only, it may GET
ConfigMaps to compare controller-desired gateway configuration to the
per-Pod applied hash; do not store secrets in ConfigMaps. Workload Pods do
not receive node hostPath mounts. OpenVPN upstream containers need NET_ADMIN,
MKNOD and `/dev/net/tun`; the **controller-rendered gateway container is
privileged** so it can set IPv4 forwarding in its Pod network namespace even
when ordinary containers receive read-only `/proc/sys`. Privilege is not a
bounded NET_ADMIN/BPF capability grant. The Gateway Pod requests no unsafe
sysctl and needs no kubelet `allowedUnsafeSysctls`; it does not share host
network/PID/IPC namespaces or mount hostPath volumes. A namespace enforcing
Pod Security Baseline or Restricted rejects this Gateway Pod; use a dedicated,
administrator-controlled namespace that explicitly permits privileged Gateway
Pods. The upstream, agent, controller, webhook and selected workload security
contexts are unchanged. The controller/webhook run nonroot with no added
capabilities and read-only root filesystems.

The webhook bootstraps its serving certificate in a memory-backed private
`/tls` volume and stores the identity in the namespaced
`ratatoskr-webhook-tls` Secret. Helm never renders certificate private keys.
The webhook ServiceAccount may create this Secret and update the named webhook
CA bundles. Preserve that Secret on normal upgrades; coordinate CA rotation
rather than removing it while admission has `failurePolicy: Fail`.

With controller leader election enabled, a namespaced Lease is used; webhook
replicas use the same TLS Secret. Only one Helm release per cluster is
supported because admission configurations and ClusterRoles have fixed names.
Metrics Services and optional Prometheus Operator monitors are described in
[the monitoring guide](../../docs/monitoring.md). Metrics HTTP is unauthenticated;
the default metrics ingress permits any source reachable to these ports.

**Ingress policies:** With `networkPolicy.enabled=true`, the chart selects
controller, webhook, and (only in agent mode) agent Pods by component labels and
allows only their listening ports. Probe and API-server source IPs vary among
clusters, so these portable policies do not restrict ingress source CIDRs.
They deliberately do **not** isolate egress: Kubernetes API, DNS, node CRI and
gateway registration/control-plane paths must stay reachable. Set
`networkPolicy.enabled=false` to render **no chart-managed NetworkPolicies**;
review any namespace-wide policies separately. The controller manages gateway
Pod ingress policies dynamically in EgressGateway namespaces; this chart flag
does not weaken or override those gateway policies. CNIs must enforce the
standard networking.k8s.io/v1 NetworkPolicy API for ingress restrictions to
have effect.

**Exit geolocation:** `metrics.geolocation.enabled=true` (default) asks
eligible token-free providers for the upstream exit IP on a bounded
`metrics.geolocation.interval` (default `1m`). This creates **outbound**
third-party lookups through the VPN; set it to false if your provider terms or
privacy policy prohibit them. Setting `metrics.enabled=false` also disables
geolocation. See [geolocation](../../docs/geolocation.md) for provider
agreement, map interpretation, freshness, and privacy.

## Upgrade and validate

Chart CRDs in `crds/` install on first install but **Helm does not upgrade or
delete CRDs automatically**. Review schema changes and apply updated CRDs
separately before upgrading the chart. Verify webhook rollout/CA bundles and
controller readiness after upgrade; scale controller replicas only with leader
election enabled. For offline checks run
`python3 charts/ratatoskr/tests/check_chart.py` (requires Helm and PyYAML).
That checker lints defaults/dev overrides, parses templates and checks RBAC,
security contexts and chart archive contents. Runtime packet-level
compatibility is a separate validation; chart lint is not traffic proof.

## Metrics and dashboard

Metrics default to enabled on controller :8080, webhook :9904, agent :9903
and dynamically managed gateway Pods :9902. Metrics ingress defaults to **any
source** on these ports; optional `metrics.ingress` namespace and Pod selectors
can restrict scraping. Metrics HTTP is unauthenticated, so secure reachability
with cluster policy as needed.
Set `metrics.enabled=false` to disable listeners and operator metrics Services.
Prometheus Operator CRDs are optional. Monitors default to `enabled: auto` and
are created when their CRDs are installed; gateway discovery includes all
namespaces by default. `metrics.serviceMonitor.enabled`
selects operator Services; `metrics.podMonitor.enabled` discovers Gateway Pods
in opted-in namespaces. Helm checks the enabled monitor CRDs. Import the
packaged Grafana JSON from `dashboards/ratatoskr-overview.json`, or set
`metrics.dashboard.enabled=true` to install a Grafana-sidecar ConfigMap.
See [monitoring details](../../docs/monitoring.md) for access and metric
interpretation.
