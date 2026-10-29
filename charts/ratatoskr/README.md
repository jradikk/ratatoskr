# Ratatoskr M2 Helm chart

Install into one namespace (for example `helm upgrade --install ratatoskr
charts/ratatoskr --namespace ratatoskr-system --create-namespace`).
`operatorNamespace`, if set, must equal the Helm release namespace. The chart
installs the controller, admission webhook, ServiceAccounts, RBAC, and a
portable webhook ingress NetworkPolicy. The controller creates gateway
Deployments, ConfigMaps, and Services in EgressGateway namespaces at runtime;
**the chart does not create a gateway pod or gateway Service**.

M2 only accepts `driver: init` and `datapath: iproute`. The injected workload
init container needs `NET_ADMIN`; gateway containers need `NET_ADMIN`, while
the OpenVPN upstream needs `NET_ADMIN`, `MKNOD`, `/dev/net/tun`, and a
memory-backed `/run/ratatoskr`. The Go controller/webhook own that dynamic
pod-spec construction, not the chart. `exclusions.serviceCIDRs` is for
clusters whose service CIDR cannot be discovered reliably; `extraCIDRs` adds
other direct-route exclusions. The chart passes these settings as comma-joined
environment values to the controller and webhook.

**TLS:** No private key is rendered by Helm. The webhook Deployment init
container executes its own image with `--bootstrap-tls`, using a memory-backed
`/tls` emptyDir shared with the serving webhook (`--tls-dir=/tls`). Bootstrap
creates or reads the namespaced `ratatoskr-webhook-tls` Secret, writes certificate
and key into `/tls`, and patches CA bundles on `ratatoskr-pods` and
`ratatoskr-validation` webhook configurations. It must retry until the
configurations are visible. Serving replicas each bootstrap into their own
memory-backed volume. The webhook Service is `ratatoskr-webhook` in the Helm
release namespace. The chart only grants Secret creation in that namespace,
get/update/patch for that exact Secret name, and get/patch on the two named
webhook configurations. Kubernetes RBAC cannot constrain Secret `create` to a
resource name, nor permit metadata-only Secret `get`; the controller has
cluster-wide Secret `get` solely for PartialObjectMetadata reads and must never
fetch or log Secret data.

**Init-mode gateway address changes:** Clients connect to gateway **pod IPs**,
not the gateway Service VIP. An M2 gateway pod restart or replacement can
change its IP, and existing workload init containers do not rerun by
themselves. The controller must roll the affected client pods in a controlled
manner after endpoints change (or an operator must restart them) to reprogram
routes; a Service VIP is **not** a substitute for this rollout. NetworkPolicy
here only restricts webhook ingress to ports 9443 and 8081 (the latter is
needed for kubelet probes). It does not attempt to infer API-server or node
CIDRs or rely on a CNI extension.
