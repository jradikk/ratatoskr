# Monitoring Ratatoskr

## Minimal setup

```yaml
metrics:
  enabled: true
```

This is also the default. Metrics endpoints allow any reachable source, and
ServiceMonitor/PodMonitor resources are created automatically when their CRDs
are installed. No gateway namespace opt-in label is needed. Prometheus must
still be configured to select these monitors; see troubleshooting below if your
Prometheus installation requires particular monitor labels.


Metrics are unauthenticated HTTP. With `metrics.enabled=true` (default),
controller listens at :8080, webhook :9904, agent :9903 and dynamically
managed gateway Pods :9902. Chart metrics Services select operator Pods;
controller-created gateway Services/ingress are separate. Health uses separate
ports. Turn metrics off to disable listeners/Services and roll gateway Pods.

## Connect kube-prometheus-stack

First install kube-prometheus-stack (including the Prometheus Operator CRDs) in
namespace `monitoring` under Helm release name `monitoring`. The example below
assumes its Prometheus Pod has label `app.kubernetes.io/name=prometheus` and
that Prometheus selects ServiceMonitor/PodMonitor objects with label
`release=monitoring`. **Check your actual installation** before using these
selectors:

```sh
kubectl -n monitoring get pods --show-labels
kubectl -n monitoring get prometheus -o yaml
```

The Prometheus custom resource must select monitors in `ratatoskr-system`
(`serviceMonitorNamespaceSelector` and `podMonitorNamespaceSelector`) and
select their label `release=monitoring` (`serviceMonitorSelector` and
`podMonitorSelector`). Configure those selectors on your Prometheus installation
if they differ; merely creating monitor objects will not make them targets.

Save this **complete** values file as `monitoring-values.yaml` (change names and
labels to match the two checks above). It contains no VPN credentials:

```yaml
metrics:
  enabled: true
  ingress:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: monitoring
    podSelector:
      matchLabels:
        app.kubernetes.io/name: prometheus
  serviceMonitor:
    enabled: true
    labels:
      release: monitoring
    interval: 30s
    scrapeTimeout: 10s
  podMonitor:
    enabled: true
    labels:
      release: monitoring
    namespaceSelector:
      any: true
    interval: 30s
    scrapeTimeout: 10s
  dashboard:
    enabled: false
```

Install or upgrade Ratatoskr **from this repository's chart source** (no
published chart is required for this procedure):

```sh
helm upgrade --install ratatoskr charts/ratatoskr \
  --namespace ratatoskr-system --create-namespace \
  --values monitoring-values.yaml --wait --timeout 5m
```

The chart must render `ServiceMonitor` and `PodMonitor`; without their
Prometheus Operator CRDs, the upgrade fails clearly rather than installing
nonfunctional monitors. Opt in only the namespaces containing Gateway Pods
that you intend to scrape (substitute the real namespace):

```sh
# Gateway discovery includes all namespaces by default.
kubectl -n ratatoskr-system get servicemonitor,podmonitor
kubectl -n ratatoskr-system get svc ratatoskr-controller-metrics ratatoskr-webhook-metrics ratatoskr-agent-metrics
```

The agent metrics Service is absent if `driver=init`. Confirm your Prometheus
Targets view shows the three operator Services (in agent mode) and authorized
Gateway Pods, then query `ratatoskr_gateway_upstream_healthy` in Prometheus.
No target is evidence of discovery/scrape success until it reports `UP`.

For Grafana, open **Dashboards → New → Import**, upload
`dashboards/ratatoskr-overview.json` from this repository, choose the
Prometheus datasource variable, and select namespace/gateway/pod filters.
Alternatively set `metrics.dashboard.enabled=true` in the values file and
upgrade: the chart installs a `ratatoskr-dashboard` ConfigMap labeled
`grafana_dashboard=1`. This alternative needs a Grafana dashboard sidecar
configured to discover ConfigMaps in `ratatoskr-system`; importing manually
needs no sidecar.

### No targets or empty panels?

1. Confirm the Prometheus instance selects `release=monitoring` and searches
   monitor objects in `ratatoskr-system`; kube-prometheus-stack installations
   can use different `serviceMonitorSelector`, `podMonitorSelector` or
   corresponding namespace selectors. Compare them to the rendered monitor
   labels/namespace, not just the Helm release name.
2. Confirm any custom namespace selector includes the Gateway namespace, and the PodMonitor selects
   it, Gateway Pods exist and expose the named `metrics` port, and
   `metrics.enabled=true`. A Gateway Service alone does not satisfy PodMonitor
   discovery.
3. If scrape restrictions were configured, confirm Prometheus Pod and
   namespace labels match the configured `metrics.ingress` selectors. Adjust
   the values file if collector labels differ; disabling all NetworkPolicies
   is not necessary.
4. Check Prometheus Targets and scrape errors first. A blank dashboard can
   mean no authorized targets, a wrong datasource, or missing target relabels;
   it does not establish zero traffic or zero peers.

## Scrape security

With `metrics.enabled=true` (default), metrics ingress admits **any source**
on the metrics ports, including non-Pod sources reachable through your network.
Operator HTTP Services are ClusterIP; a ClusterIP is not authentication or
an ingress access-control policy. Health/admission/Gateway transport rules
are unchanged by the metrics selector defaults. To restrict scraping, set
`metrics.ingress.namespaceSelector` and/or `podSelector`: a namespace selector
alone permits all Pods in matching namespaces; a Pod selector alone permits
matching Pods across all namespaces; both selectors match jointly. Empty
`{}`+`{}` means unrestricted. Supply actual collector labels after inspecting
your Prometheus Pods and namespaces. The configured metrics ports only are
restricted; there is **no egress isolation**, preserving Kubernetes API/CRI/DNS
and gateway connectivity. `networkPolicy.enabled=false` suppresses chart
policies, so provide your own restrictions. Your CNI must enforce the standard
NetworkPolicy API. Do not expose unauthenticated metrics endpoints publicly.

## Discovery and dashboard

With just `metrics.enabled: true`, the chart automatically creates a
ServiceMonitor for operator Services and a PodMonitor for gateway Pods whenever
their respective CRDs are installed. Gateway discovery includes all namespaces
by default, selecting only Ratatoskr gateway labels. Missing CRDs skip automatic
monitors without blocking installation. Install Prometheus Operator first, then
upgrade Ratatoskr to create them.

Advanced settings can force either monitor on (`enabled: true`, which errors if
its CRD is missing) or off (`enabled: false`). The default is `enabled: auto`.
Monitor labels and any custom namespace selector must agree with your Prometheus
installation's discovery settings. The chart cannot override an existing
Prometheus instance's restrictive ServiceMonitor/PodMonitor selectors.
Interval defaults to 30s, scrape timeout 10s. Both monitors can coexist:
operator Services and gateway Pods are distinct scrape targets. Explicit
PodMonitor relabelings provide `namespace`, `pod`, `gateway`, `gateway_uid`,
`profile`; ServiceMonitor provides namespace/pod. These are Kubernetes target
labels, not secret-bearing in-process series labels.

Import `dashboards/ratatoskr-overview.json` into Grafana; set its Prometheus
datasource variable. Or set `metrics.dashboard.enabled=true` to install the
same JSON as a ConfigMap labeled `grafana_dashboard=1` by default for a
Grafana dashboard sidecar. Target label filtering requires the configured
PodMonitor relabelings or equivalent labels in a custom scrape setup.

## Interpreting metrics

`ratatoskr_gateway_upstream_healthy` and
`ratatoskr_gateway_effective_mtu_bytes` report readiness and measured MTU,
not client traffic delivery. Gateway and agent programming
`*_attempts_total`, `*_errors_total`, and `*_duration_seconds` histograms
report completed operations. Gateway `ratatoskr_gateway_link_*{role=...}`
are resettable kernel samples, not monotonic counter evidence; check
`ratatoskr_gateway_link_sample_ok`. Gateway
`ratatoskr_gateway_wireguard_{installed_peers,handshaken_peers,latest_handshake_age_seconds,receive_bytes,transmit_bytes}`
and `ratatoskr_gateway_plaintext_geneve_{drop_packets,drop_bytes}` are
conditional on encrypted mode. A handshaken peer need not be healthy now;
check `_sample_ok`. When available,
`ratatoskr_gateway_forwarded_connections{protocol="TCP|UDP"}` estimates
scoped conntrack entries; `_sample_ok=0` or missing is **unknown**, not zero.
Dashboard panels do not prove end-to-end packet attribution. Do not put
credentials, Pod/client IPs, tokens or VPN profile data in metric labels.
