# Per-workload domain routing DNS barrier

This library learns IPv4 /32 selectors from a workload's observed DNS answers
and applies them synchronously **before returning a matched A answer**. It does
not create listeners, network namespaces, nft rules, API watchers or credentials.
The trusted node agent supplies those integrations. Each `Proxy` is one workload
and one authorized policy generation; never share a proxy between clients.

## API and integration order

- `New(Options)` configures include/exclude rules, a literal IPv4 resolver:port,
  `Apply(context.Context, Update) error`, optional namespace-aware `Exchange`,
  optional persisted `Restore`, clock and bounded limits.
- `Rule` combines original `CIDRs` OR `Domains` with unchanged qualified `Ports`.
  Domains use exact canonical ASCII names or leading `*.example.com` (at least
  two suffix labels, one or multiple sublabels, not the apex). Map API
  `matchName`/`matchPattern` to the corresponding strings.
- `ServeDNS` implements miekg/dns.Handler. Agent-created loopback1053 UDP/TCP
  sockets must belong to the verified target netns; only the intended resolver
  traffic should be redirected. Agent forward sockets must use the authorized
  resolver route and skip owned DNS interception via its control mark. Supply
  `ExchangeFunc` for that integration: the default opens ordinary sockets in the
  caller's current netns, does not enter a netns, and is not an authorization gate.
- `Apply` receives cloned, deterministic `Update{Rules, State}`. Serialize it
  with workload reconciliation, recheck current Pod/sandbox/gateway/policy
  identities, program the backend and persist trusted state **before nil**. A
  backend/persistence failure must fence/retry safely; a callback that partially
  mutates routing but returns error cannot be rolled back by this library.
- `Snapshot()`/`Rules()` return independent snapshots. `Binding` aliases
  `datapath.DomainBinding`: original rule index, address, Unix-second expiry and
  retained bit; no hostname is persisted. Bind restoration to the authenticated
  Pod UID, sandbox and policy UID/generation/hash; `New` validates the shape,
  not Kubernetes authority. Call `Sync(ctx)` before listener readiness to apply
  restoration, and periodically to withdraw expired exclude bypasses.

A domain-only unresolved rule is omitted, **never** compiled as an empty-CIDR
all-destinations rule. Static CIDRs remain active independently of DNS learning.
Ports remain attached to their original rules, even when multiple domains share
an IP. The returned rule list's position may differ from original rule index;
persisted bindings always retain the original index.

## Lifetime and failures

Include learned /32s stay VPN-protected indefinitely, including after DNS TTL
expiry. Do not evict expired include entries into default-direct routing. They
are removed only by explicit policy replacement/removal or workload teardown;
restore them before reopening after an agent restart. Capacity exhaustion returns
SERVFAIL for new mappings instead of evicting protected addresses.

Exclude learned /32s expire and revert to the default VPN path after successful
Sync application. Failed application retains the previous snapshot; the agent
must fence or retry to avoid leaving a direct bypass active beyond its TTL.
Negative/no-address responses do not remove still-valid entries. Address/rule
lifetime uses a conservative union when multiple names resolve to the same IP.

Only A records in Answer reachable from the exact question through a bounded,
noncyclic CNAME chain grant rules. Unrelated Additional/Authority addresses never
grant routing and are stripped from matched replies so downstream caches cannot
learn unprogrammed addresses. Matched replies contain only the question-reachable
A/CNAME chain; transaction identity is validated even for nonmatching passthrough. Duplicate A/CNAME TTLs use their minimum; ambiguous aliases,
malformed transaction identity/classes/addresses, TTL0 and capacity excess fail
closed. Returned TTL is capped to A/CNAME lifetime, configured maximum and
application latency. UDP truncation retries once via TCP at the same resolver;
a still-truncated response is never released. AAAA/non-A answers pass without
learning; the existing IPv6 workload fence is required. This is IPv4 routing,
not IPv6 support or a hostname identity verifier.

Defaults: 64 rules, 64 domains per rule, 4096 rule/address bindings, 256 total
response RRs, 16 CNAME hops, 1h maximum TTL and 3s query timeout. Lower limits are
configurable within hard upper bounds. Expanded CIDR/port rules must also fit
the shared datapath validation limit. There are no background goroutines;
listeners and shutdown cancellation belong to the agent.

DNS-derived IP routing cannot distinguish tenants sharing an address, verify
TLS/HTTP hostname identity, or discover hardcoded addresses/DoH/custom resolver
traffic outside the captured gateway-DNS contract. Include misses retain normal
include default-direct behavior, but a selected observed A answer is not given
back before routing/persistence commits. DNS upstream data and resolver
selection are trusted; this library does not implement DNSSEC validation.

## Offline checks

```sh
go test ./pkg/fqdn/...
go test -race ./pkg/fqdn/...
go vet ./pkg/fqdn/...
```

Tests inject DNS exchanges, clocks, writers and application callbacks; they do
not query external DNS, read credentials or mutate network namespaces. Real
agent/CNI listener interception requires separate integration verification.
