# M3 — policy, DNS and safety implementation report

Status: **code and local component checks passed; packet-level e2e remains deferred to the final project gate**. This is not a claim that the live selective-policy, VPN DNS, spoof-packet or MTU/payload scenarios passed.

## Built

- Bounded `EgressPolicy` compiler for IPv4 include/exclude CIDRs and TCP/UDP ports/ranges (up to 4,096 expanded selectors); multiple matching policies and references to a different gateway are rejected. `iproute` now uses nft route/output marks plus policy routing without client REDIRECT or DNAT. Steered matches with no healthy endpoint use the unreachable fallback, not main routing; changes preserve foreign rules.
- Higher-priority cloud-metadata prohibition for default `allowCloudMetadata: false`; an explicit true value permits the normal route. Client programming rejects a non-link-local IPv6 address on eth0 rather than silently allowing an IPv6 bypass at initialization.
- Discovery and status reporting for Node pod CIDRs/IPs, configured or ServiceCIDR API ranges, API/DNS endpoints, gateway PodIPs, link-local and extra CIDRs. Unknown/invalid pod or Service CIDRs prevent readiness. Controller renders gateway DNS Service and an owner-referenced ingress NetworkPolicy.
- `dns.mode: gateway` uses its own Service ClusterIP as workload nameserver. Gateway forwarder sends cluster names/reverse ranges to kube-dns over the cluster path; external UDP/TCP DNS uses only a socket bound to upstream0 and marked into the VPN routing table. External queries return SERVFAIL when upstream is unhealthy, without fallback to eth0. The gateway pod keeps cluster DNS.
- Gateway `/info` reports measured eth0, GENEVE and upstream MTUs, effective inner MTU and MSS. Effective MTU below 576 fails; 576–1279 is IPv4-safe but receives an IPv6-minimum warning. Controller consumes measurements rather than inventing them.
- Chart RBAC covers the newly read cluster resources and the dynamically rendered NetworkPolicy; static checks cover the added rules.

## Checks run (October 29, 2026)

- `make test` (race/coverage), `make lint`, `make vet`, `make build`, `make test-privileged`: **passed** after integration.
- Chart lint and complete default/dev template, RBAC, admission and driver-scope static checks: **passed**.
- Scoped compiler, datapath, DNS forwarder, controller and webhook tests: **passed**; the privileged netns tests check routes, nft rules, exclusions, metadata and no-endpoint fail-close without sending workload traffic.
- No M3 image deployment or gateway/workload packet-level scenario was run. The existing M2 operator Deployments remain Available on the flannel k3d cluster; that is **not** an M3 runtime result.

## Deferred and open issues

- `make e2e` and `make e2e-live` were **not run** by the user's instruction. Live steps 7–9/12, spoofed GENEVE packet drop and multi-MB transfer remain unverified until the final gate; no report.json is claimed.
- The M2 `init` driver still needs client-pod rollout after a gateway PodIP change (approved ADR-0012); M5 agent must update in place.
- Only IPv4 is implemented. IPv6 present at init is rejected; IPv6 assigned to a pod **after** one-time init, or a nonstandard interface name, needs an additional runtime guard before claiming production fail-close in dual-stack clusters.
- Gateway DNS uses the configurable `UPSTREAM_DNS_IP` (default 1.1.1.1); some VPN providers may block external resolvers. Provider-specific resolver discovery and DNS resilience require validation at the final gate.
- M4 encryption, M5 capability-free agent, M6 eBPF, M7 HA/observability, M8 compatibility matrix and M9 release remain pending. No VPN config, credential, private key or token was used or copied into this report.
