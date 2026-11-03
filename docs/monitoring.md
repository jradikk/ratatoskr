# Monitoring Ratatoskr

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
      matchLabels:
        ratatoskr.skaldhall.io/metrics: enabled
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
kubectl label namespace <gateway-namespace> ratatoskr.skaldhall.io/metrics=enabled --overwrite
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
2. Confirm the Gateway namespace has the opt-in label, the PodMonitor selects
   it, Gateway Pods exist and expose the named `metrics` port, and
   `metrics.enabled=true`. A Gateway Service alone does not satisfy PodMonitor
   discovery.
3. Confirm the Prometheus Pod and namespace labels match **both**
   `metrics.ingress` selectors. The policies admit the metrics ports only from
   that intersection. If the collector uses different labels, adjust the
   values file and upgrade rather than turning off NetworkPolicy.
4. Check Prometheus Targets and scrape errors first. A blank dashboard can
   mean no authorized targets, a wrong datasource, or missing target relabels;
   it does not establish zero traffic or zero peers.

## Scrape security

The metrics NetworkPolicy ingress rule requires *both* namespace and Pod
selectors. Default namespace label `kubernetes.io/metadata.name=monitoring`
and Pod label `app.kubernetes.io/name=prometheus` should be changed to your
collector labels. Empty selectors fail template validation. There is **no
egress isolation**, preserving Kubernetes API/CRI/DNS/gateway connectivity.
`networkPolicy.enabled=false` suppresses chart policies, so provide your own
scrape restriction. The CNI must enforce standard NetworkPolicy; never expose
these unauthenticated endpoints publicly.

## Discovery and dashboard

ServiceMonitor (`metrics.serviceMonitor.enabled`) selects controller, webhook
and agent metrics Services in the release namespace. PodMonitor
(`metrics.podMonitor.enabled`) selects managed Gateway Pods in namespaces
matching `metrics.podMonitor.namespaceSelector`; default namespace opt-in is
`ratatoskr.skaldhall.io/metrics=enabled`. Each is independently opt-in and
requires its `monitoring.coreos.com/v1` CRD. The chart fails when an enabled
monitor CRD is absent. Their labels must match your Prometheus selector.
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
