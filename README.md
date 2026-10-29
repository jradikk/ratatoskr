# Ratatoskr

Label-driven egress gateways for Kubernetes. Create an `EgressGateway` backed by a
VPN (OpenVPN, WireGuard, AmneziaWG, IPsec or your own container), label a
workload with `ratatoskr.skaldhall.io/gateway: <name>`, and its outbound traffic —
all of it or a policy-selected subset — leaves through that VPN. If the gateway
or VPN is down, steered traffic fails closed.

> Status: pre-alpha (milestone M0). See [docs/design.md](docs/design.md) and
> [docs/adr/](docs/adr/).

## Developer quickstart (k3d)

```sh
hack/bootstrap.sh      # tools, kernel modules (idempotent)
make test              # unit tests
make dev-up            # k3d cluster, flannel variant (VARIANT=cilium|cilium-wg|calico, MESH=sidecar|ambient)
make dev-deploy        # build images, import into k3d, helm install
make dev-down
```

The live end-to-end suite needs an OpenVPN client config, never committed:

```sh
export RATATOSKR_E2E_OVPN=/path/to/client.ovpn
export RATATOSKR_E2E_OVPN_AUTH=/path/to/auth.txt   # optional
export RATATOSKR_E2E_EXPECT_COUNTRY=DE             # optional
make e2e-live
```

## License

Apache-2.0
