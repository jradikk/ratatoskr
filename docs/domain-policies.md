# DNS domain policies

Domain rules select IPv4 addresses learned from the DNS answers your application
receives. They support both VPN inclusion and exclusion without adding an
application sidecar.

## Requirements

- Install Ratatoskr with `driver: agent`.
- Set the selected gateway's `spec.dns.mode` to `gateway` before creating the
  application Pods. Admission injects the gateway DNS Service as their resolver.
- Applications must use that configured resolver over ordinary UDP/TCP port 53.
  Private DNS-over-HTTPS/TLS resolvers, hardcoded IP addresses, or DNS caches
  populated before enrollment cannot be identified as domains by Ratatoskr.
- Domain routing supports IPv4. AAAA DNS responses remain unchanged, but the
  workload IPv6 guard still prevents unsupported IPv6 egress.

Init-driver domain policies are rejected with a configuration error. Existing
Pods whose DNS settings were not injected need to be recreated; changing the
Gateway setting does not rewrite an already-running Pod's resolver.

## Exclude a CDN from the VPN

```yaml
apiVersion: ratatoskr.skaldhall.io/v1alpha1
kind: EgressPolicy
metadata:
  name: direct-downloads
  namespace: apps
spec:
  gatewayRef:
    name: berlin
    namespace: ratatoskr
  workloadSelector:
    matchLabels:
      app: my-app
  mode: exclude
  rules:
    - domains:
        - matchName: downloads.example.com
        - matchPattern: "*.assets.example.com"
      ports:
        - protocol: TCP
          port: 443
```

Use canonical lowercase ASCII DNS names without a trailing dot. `matchName`
selects exactly one name. `*.assets.example.com` selects one or more subdomain
labels, including `a.b.assets.example.com`, but **not** `assets.example.com`.
Add an exact selector if the apex is also required. Each selector sets exactly
one of `matchName` or `matchPattern`; URLs, IP literals, and broad `*.com`
patterns are not accepted.

`mode: exclude` routes matching learned addresses/ports through normal Pod
networking and keeps other non-excluded traffic on the VPN. Use `mode: include`
to tunnel only matching destinations. CIDRs and domains within one rule are
**OR alternatives**, and the same port restrictions apply to both. Omitting
ports matches all traffic to those addresses. Avoid overlapping policies that
select the same Pod.

## DNS response and routing order

The node agent owns per-workload UDP/TCP DNS listeners and an isolated redirect
inside the selected workload's network namespace. It forwards requests to the
authorized gateway DNS Service, follows bounded CNAME chains in the response,
and learns only relevant IPv4 Answer records—not unrelated Additional records.
It programs and persists the routing update **before returning a successful
matched DNS answer**. No gateway control endpoint or workload API token is added.

Unresolved domain-only rules match no addresses; they are never interpreted as
an empty-CIDR wildcard. DNS/application failures do not grant a direct exception.
Matched zero-TTL answers, excessive mappings, or failed routing updates are
refused rather than returning an answer before routes are ready.

## Expiry, restart and recovery

- **Exclude:** learned direct exceptions expire according to bounded DNS/CNAME
  TTLs. Expiry successfully removes the exception before it is forgotten; the
  address returns to the VPN path.
- **Include:** learned addresses remain protected through the VPN after DNS TTL
  expiry, because the application may retain those addresses. Protected mappings
  are bounded; capacity exhaustion refuses additional DNS answers instead of
  evicting entries into direct egress.
- Bindings are persisted as non-secret addresses associated with the Pod UID,
  policy UID/generation, and agent-owned configuration hash. Agent restart restores
  valid retained state before reopening the path.
- A partial programming or persistence failure fences the workload rather than
  returning a successful answer. Recovery from this persistent quarantine requires
  Pod recreation.
- Changing a domain policy revision or its DNS Service while a domain runtime is
  active currently requires recreating selected Pods. Ordinary CIDR-only policies
  retain their existing in-place agent reconciliation behavior.

## CDN and privacy limitations

This is **DNS-derived IP routing, not HTTP/TLS hostname verification**. CDN
customers can share the same address. If an excluded domain resolves to an IP,
other traffic from that Pod to the same IP and allowed port can also bypass the
VPN. Per-workload tracking narrows that scope but cannot eliminate shared-IP
ambiguity. Include mappings may also conservatively keep old CDN IPs on the VPN.

Established connections are not guaranteed to migrate seamlessly when rules or
exit endpoints change. Test with fresh connections. Standard NetworkPolicy is
still needed for traffic denial; an exclusion means **direct routing**, not drop.
