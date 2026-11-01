# M2 — control-plane MVP implementation report

Status: **implementation and local component smoke pass; packet-level e2e is deferred to the final project gate**. This does not claim that the full live suite or the original no-client-restart gateway replacement test passed.

## Built

- Namespaced `EgressGateway` and `EgressPolicy` Go API, complete generated CRDs and API-server-accepted schema/CEL CIDR rules. Status includes gateway IDs, healthy PodIP endpoints and readiness conditions.
- controller-runtime reconciliation of a single-replica OpenVPN gateway Deployment, UDP/6081 discovery Service and non-secret ConfigMap. Gateway programming leaves the main default route on eth0; only its upstream container mounts the provider Secret. The controller selects authorized workload PodIPs, tracks endpoint health, records conditions/Events and patches `datapath-ready` only after the injected init exits successfully.
- Mutating/validating admission rejects disallowed namespaces, unallocated gateways, unsupported M2 modes, matching unimplemented policies and live Pod opt-in changes. CREATE validation independently recomputes the authorized gateway configuration; plain forged annotations or missing init cannot bypass fail-close. The M2 init container obtains its PodIP/UID and eth0 MTU after CNI setup.
- Kubernetes-managed TLS bootstrap reuses its Kubernetes Secret, writes local serving files to a private memory-backed directory, and retries registration briefly without ignoring authorization errors. Helm installs component Deployments/Services, scoped RBAC and fail-closed admission hooks. Chart rejects agent/eBPF before those milestones.
- Gateway reloads its operator-owned ConfigMap, updates the source-verification allowlist, and drops forwarded traffic on a missing/invalid replacement.
- `make dev-deploy` now server-side applies complete CRDs before Helm upgrade (Helm does not add newly introduced CRDs on upgrade of the existing M0 release). The k3d dev values explicitly set pod/service CIDRs until automatic discovery is built in M3.

## Checks run (October 29, 2026)

- `make test` (race/coverage), `make lint`, `make vet`, `make build`, `make test-privileged`: **passed**.
- `helm lint charts/ratatoskr --strict` and chart static checks for template completeness, webhook routing, selectors, TLS volume, scoped RBAC and supported modes: **passed**.
- CRDs: `kubectl apply --dry-run=server -f charts/ratatoskr/crds/`: **accepted** on the existing flannel k3d API server.
- `make dev-deploy`: built/imported six local images and upgraded the chart; the subsequent upgrade with explicit CRD application succeeded. Controller and webhook Deployments each became **1/1 Available**; the TLS Secret exists (only its type was inspected, never its data); both CRDs are served.
- Server-side Pod admission dry-runs: unlabeled Pod **allowed**; a Pod opting into a nonexistent gateway **denied**. No Pod was created and no workload/gateway packet was sent by these checks.

## Deferred and limitations

- `make e2e` and `make e2e-live` have **not** run. Neither full-tunnel exit-IP behavior nor gateway-restart recovery has been packet-tested. Complete M2+ CI/live scenarios and `report.json` await the final project gate; absent `RATATOSKR_E2E_OVPN` will be a **skip, not a pass**.
- User-approved ADR-0012 option 1: after a gateway PodIP change, `init` clients require rollout/recreation; until then their fixed-remote GENEVE attempts fail closed. The M5 agent must update those endpoints in place without restarting clients.
- M2 supports only unencrypted `iproute`, OpenVPN, one gateway replica and cluster DNS. Policies/DNS gateway mode, WireGuard, capability-free restricted workloads, eBPF, HA and observability remain their respective later milestones. Unknown cluster CIDRs fail closed; automatic discovery and metadata handling need M3. Additional gateway ingress policies and validation policy defence-in-depth are also pending M3 security work.
- Only k3d/flannel/no-mesh operator startup and admission dry-runs were exercised; the CNI/mesh matrix and upstream traffic remain unverified. No VPN credentials, configs, tokens or private keys were used or recorded.
