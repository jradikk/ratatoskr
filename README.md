# Ratatoskr

Label-driven egress gateways for Kubernetes. Create an `EgressGateway` backed by a
VPN (OpenVPN, WireGuard, AmneziaWG, IPsec or your own container), label a
workload with `ratatoskr.skaldhall.io/gateway: <name>`, and its outbound traffic —
all of it or a policy-selected subset — leaves through that VPN. If the gateway
or VPN is down, steered traffic fails closed.

> **Status: pre-alpha; NOT READY FOR PRODUCTION.** Final-gate checks passed
> two flannel/no-mesh/init fake traffic subsets (iproute and eBPF), plus scoped
> flannel/no-mesh agent/iproute synthetic WireGuard peer startup/revocation,
> fresh-connection two-replica HA, and witnessed selected-destination outage/
> recovery with packet-correlated fail-close. An independently reviewed owned
> Pod-bound token confirms Kubernetes UID/ServiceAccount/audience semantics,
> **not** that the gateway made its own TokenReview call. These are partial
> fixtures, not a full M8 matrix or release pass. Plaintext GENEVE denial,
> actual gateway-call evidence, Linux 5.10 runtime, broader CNI/mesh cases,
> full observability and release provenance remain unverified.
> No release has been published. See [final-gate evidence](docs/milestones/m9/final-gate.md),
> [compatibility inventory](docs/milestones/m8/report.md), and [design](docs/design.md).

## Developer quickstart (k3d)

```sh
hack/bootstrap.sh      # tools, kernel modules (idempotent)
make test              # unit tests
make dev-up            # k3d cluster, flannel variant (VARIANT=cilium|cilium-wg|calico, MESH=sidecar|ambient)
make dev-deploy        # build images, import into k3d, helm install
make dev-down
```

**Do not treat `make e2e` or `make e2e-live` as a release pass:** the M8
matrix deliberately returns INCOMPLETE for missing CNI/mesh coverage and
unverified agent/WireGuard/HA scenario requirements, even after scoped synthetic
fixtures and direct-config subsets pass. Run traffic only at the authorized final
project gate; passing subsets are not full compatibility acceptance. An unset
live OpenVPN profile is reported as **skipped**, never passed.

The live end-to-end suite needs an OpenVPN client config, never committed:

```sh
export RATATOSKR_E2E_OVPN=/path/to/client.ovpn
export RATATOSKR_E2E_OVPN_AUTH=/path/to/auth.txt   # optional
export RATATOSKR_E2E_EXPECT_COUNTRY=DE             # optional
make e2e-live
```

## Releases

Builds and publication run exclusively in GitHub Actions when a reviewed
`vX.Y.Z` tag is pushed. The release workflow validates CI, publishes all six
multiarch images to Docker Hub, packages the matching chart in GHCR, and attaches
binaries, checksums and immutable image references to the GitHub release.
See [.github/RELEASING.md](.github/RELEASING.md) for required secrets, provenance
verification and the `v0.1.0` trigger. Configuring this workflow does not establish
full production compatibility; the acceptance limitations above still apply.

## License

Apache-2.0
