# M4 — optional WireGuard underlay implementation report

Status: **implementation and local component checks passed; final packet-level e2e is deferred**. This report does not claim that a real OpenVPN/WireGuard tunnel or live exit-IP scenario passed.

## Implemented so far

- An optional pod-IP WireGuard underlay carries the same GENEVE datapath, with dedicated kernel device, per-pod private key generated in its own netns and a fwmark route bypass for WireGuard/registration sockets. Gateway peers are added only by explicit authenticated registration, not by reading a client list. Gateway process restart revokes previously registered peers before publication.
- Gateway registration validates an audience-specific, Pod-bound ServiceAccount token through TokenReview, verifies live Pod UID/IP/namespace/gateway selection, and uses TLS with an ephemeral gateway CA/serving key held in pod process memory. Only the public CA and WG public key are published as gateway Pod annotations/status.
- Workload webhook projects a ten-minute token with dedicated audience only to Ratatoskr init; it validates Pod CREATE independently against public endpoint identity, rejects token-volume mounts in other containers and malformed/wrong keys/certificates. Client init authenticates the peer over pinned TLS before applying encrypted routes.
- A Pod watch and 24-hour backstop remove stale peers; a refreshed authorized Pod retains registration. Controller renders encrypted gateway Pod identity, projected API token mounted only into the gateway container, WG/HTTPS ingress rules and owner-chain-verified public endpoint status.

## Validation completed so far

- After the VM was upgraded to 7,913 MiB RAM, repository-wide `make test`, `make test-privileged`, `make lint`, `make vet`, `make build`, Helm/chart static checks and API-server CRD dry-run **passed after controller integration**. Initial 3,895 MiB VM runs had OOM-killed lint; no VM provisioning or memory workaround was attempted.
- Privileged two-netns packet test confirmed plain GENEVE UDP/6081 is dropped on eth0, authenticated WG packets reach the gateway GENEVE accept verifier, and an authenticated WG packet with forged inner source is rejected.
- Scoped TLS/TokenReview, Pod watch, webhook admission, kernel baseline and init registration tests passed with race detection. None used a real VPN config or credential.
- `make dev-deploy` built and imported six local images, applied complete CRDs, and upgraded the existing flannel k3d cluster (Helm revision 4). Controller and webhook remained 1/1 Available. `kubectl auth can-i` verified the gateway ServiceAccount can create TokenReviews and patch Pods in the operator namespace but cannot patch Pods in `default`; only permission booleans and metadata were queried, never tokens or Secret bytes.

## Not yet verified

- Live WireGuard gateway CRD reconciliation with a real upstream Secret was not performed; operator/image smoke only checked `make dev-deploy`, controller/webhook Deployments 1/1 and serviceaccount/RBAC authorization. M4 client Pod token projection against a live kubelet still needs final e2e.
- Actual cluster WireGuard key publication, TokenReview/registration, handshake, return-path traffic, deletion lifecycle and node packet capture. These are reserved for final CI/live e2e; do **not** mark them passed now.
- M5 production agent driver (capability-free workloads) and later milestones. M4 `init` clients still require rollout after a gateway PodIP or gateway process identity change (ADR-0012).
