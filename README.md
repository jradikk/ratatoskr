# Ratatoskr

Label-driven egress gateways for Kubernetes. Create an `EgressGateway` backed by a
VPN (OpenVPN, WireGuard, AmneziaWG, IPsec or your own container), label a
workload with `ratatoskr.skaldhall.io/gateway: <name>`, and its outbound traffic —
all of it or a policy-selected subset — leaves through that VPN. If the gateway
or VPN is down, steered traffic fails closed.

> **Status: pre-alpha; NOT READY FOR PRODUCTION.** M4–M7 components have local
> checks, but the final traffic gate is blocked: iproute port-selective TCP
> replies fail reverse-path validation in the NET_ADMIN-only programming init
> container, and the eBPF fake echo times out **after** packet-correlated
> gateway flower acceptance and GENEVE return reception. The precise eBPF
> socket failure remains unproven; intrinsic tc-egress metadata loss was not
> reproduced with the unchanged production program.
> The basic iproute full-tunnel fake proof passes after a return-TTL fix, but
> it does not establish selective, eBPF, CNI/mesh, HA, or live VPN acceptance.
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
matrix deliberately returns INCOMPLETE for missing CNI/mesh/agent/WireGuard/HA
coverage, even if a direct-config subset passes. Run traffic only at the final
project gate; resolve both documented datapath blockers first. An unset live
OpenVPN profile is reported as **skipped**, never passed.

The live end-to-end suite needs an OpenVPN client config, never committed:

```sh
export RATATOSKR_E2E_OVPN=/path/to/client.ovpn
export RATATOSKR_E2E_OVPN_AUTH=/path/to/auth.txt   # optional
export RATATOSKR_E2E_EXPECT_COUNTRY=DE             # optional
make e2e-live
```

## License

Apache-2.0
