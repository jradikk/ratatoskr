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
| `agent.criSocket` | `/run/containerd/containerd.sock` | Node CRI Unix socket; on k3s/k3d use `/run/k3s/containerd/containerd.sock`. |
| `clusterDomain` | `cluster.local` | Kubernetes DNS domain for webhook certificates and gateway DNS. |
| `dns.upstreamIP` | `1.1.1.1` | Gateway-mode upstream resolver, accessible over the VPN. |
| `dns.upstreamProbeURL` | empty | Optional operator-only tunnel-bound literal IPv4 HTTP(S) exit probe; leave empty for the plugin default. No credentials in URL. |
| `exclusions.serviceCIDRs`, `exclusions.podCIDRs`, `exclusions.extraCIDRs` | `[]` | Direct-network ranges; confirm cluster Pod/Service ranges before steering traffic. |
| `controller.replicas`, `webhook.replicas` | `1`, `1` | Controller replicas >1 require `controller.leaderElection.enabled=true`. |
| `networkPolicy.enabled` | `true` | Portable webhook ingress restriction to ports 9443/8081. |

Agent-mode workload wait-init is unprivileged and has no workload API token;
its readiness depends on the node agent's applied gateway-configuration
acknowledgement. Init-mode clients connect to **gateway Pod IPs**, not the
Gateway Service VIP. After endpoint IP changes, affected init workloads need
a controlled rollout to reprogram their routes. The controller surfaces a
`ClientRestartRequired` condition; agent-mode endpoints can reconcile in
place. Use EgressGateway status and conditions, not Service VIP health, to
judge endpoint readiness.

## Security and operations

The agent runs as root with hostPID/hostNetwork, NET_ADMIN/SYS_ADMIN (plus
BPF/PERFMON for eBPF), read-only node CRI socket and `/var/run/netns` mount,
and a cluster-wide token-request permission for short-lived bound registration.
**Treat the agent as node-root-equivalent** and restrict its placement and
ability to modify its ServiceAccount. In agent mode only, it may GET
ConfigMaps to compare controller-desired gateway configuration to the
per-Pod applied hash; do not store secrets in ConfigMaps. Workload Pods do
not receive node hostPath mounts. OpenVPN upstream containers need NET_ADMIN,
MKNOD and `/dev/net/tun`; gateway containers need NET_ADMIN, plus BPF/PERFMON
when eBPF is selected. The controller/webhook run nonroot with no added
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
The controller does not expose a metrics Service; gateway metrics remain
loopback-only within gateway Pods.

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
