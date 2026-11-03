# Multiple VPN profiles per gateway

Use independent profiles when your VPN provider allows only one active connection
per credential set. Ratatoskr runs one gateway Pod per profile and distributes
application Pods across the healthy gateway endpoints using stable per-Pod
selection. Applications still use a single gateway label.

## Create the Secrets

Each profile needs its own provider-approved OpenVPN credentials/configuration.
Create the Secrets in the same namespace as the gateway:

```sh
kubectl create secret generic berlin-vpn-a -n ratatoskr \
  --from-file=client.ovpn=/private/berlin-a.ovpn
kubectl create secret generic berlin-vpn-b -n ratatoskr \
  --from-file=client.ovpn=/private/berlin-b.ovpn
```

Add `--from-file=auth.txt=/private/auth-a.txt` or the matching profile's auth file
when required by your provider. Include any referenced certificates and keys in
the corresponding Secret. Never commit them or put them in Helm values.

## Define a gateway pool

```yaml
apiVersion: ratatoskr.skaldhall.io/v1alpha1
kind: EgressGateway
metadata:
  name: berlin
  namespace: ratatoskr
spec:
  replicas: 1
  upstream:
    type: openvpn
    profiles:
      - name: a
        secretRef:
          name: berlin-vpn-a
      - name: b
        secretRef:
          name: berlin-vpn-b
  failMode: closed
  encryption: none
  dns:
    mode: gateway
  allowedNamespaces:
    namespaceSelector:
      matchLabels:
        ratatoskr-access: berlin
```

Profiles and the legacy `upstream.secretRef` cannot be combined. Up to eight
profiles are supported, each with a unique name. In profile mode `replicas` must
be one: the profile list determines the number of independent gateway Pods.
The legacy single-Secret form remains available and uses `replicas` as before.

Label the application namespace with `ratatoskr-access=berlin`, and its Pod
template with `ratatoskr.skaldhall.io/gateway: berlin`. If the operator is installed
elsewhere, also set `ratatoskr.skaldhall.io/gateway-namespace: ratatoskr` on the
application Pod template. Namespace authorization still applies to the pool.

## Balancing and updates

- Balancing is **per application Pod**, not per HTTP request or connection.
- A Pod keeps its chosen healthy endpoint while the endpoint set stays stable.
- Removing or failing an endpoint moves affected application Pods to a healthy
  endpoint in agent mode. Existing connections may break when the VPN exit changes.
- With no healthy endpoint, selected traffic fails closed.
- Removing a profile deletes its operator-owned Deployment. Changing the profile
  Secret reference or image replaces that profile's gateway Pod.
- Provider session restrictions still apply; the operator cannot make two copies
  of the same credentials into two independent provider sessions.

Inspect the pool with:

```sh
kubectl get deployments,pods -n ratatoskr
kubectl describe egressgateway berlin -n ratatoskr
```

The [Grafana dashboard](monitoring.md) distinguishes gateway Pods and profile
labels, allowing you to compare health, traffic, and tracked connection counts.
