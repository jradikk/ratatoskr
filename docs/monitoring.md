# Monitoring Ratatoskr

Metrics are unauthenticated HTTP. With `metrics.enabled=true` (default),
controller listens at :8080, webhook :9904, agent :9903 and dynamically
managed gateway Pods :9902. Chart metrics Services select operator Pods;
controller-created gateway Services/ingress are separate. Health uses separate
ports. Turn metrics off to disable listeners/Services and roll gateway Pods.

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
`ratatoskr_gateway_forwarded_connections{protocol="tcp|udp"}` estimates
scoped conntrack entries; `_sample_ok=0` or missing is **unknown**, not zero.
Dashboard panels do not prove end-to-end packet attribution. Do not put
credentials, Pod/client IPs, tokens or VPN profile data in metric labels.
