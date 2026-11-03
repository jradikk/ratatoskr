package fqdn

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

type Rule struct {
	Domains []string
	CIDRs   []netip.Prefix
	Ports   []datapath.Port
}

// Binding is non-secret persisted routing state; never contains DNS names.
// The agent must authenticate the Pod/policy/gateway binding before restoration.
type Binding = datapath.DomainBinding

type Update struct {
	Rules []datapath.Rule
	State []Binding
}
type ExchangeFunc func(context.Context, *mdns.Msg, string, string) (*mdns.Msg, error)
type Limits struct {
	MaxRules, MaxDomains, MaxBindings, MaxRecords, MaxChain int
	MaxTTL, Timeout                                         time.Duration
}

func DefaultLimits() Limits { return Limits{64, 64, 4096, 256, 16, time.Hour, 3 * time.Second} }

type Options struct {
	Mode     string
	Rules    []Rule
	Resolver string
	Restore  []Binding
	Apply    func(context.Context, Update) error
	Exchange ExchangeFunc
	Clock    func() time.Time
	Limits   Limits
}

// Proxy is one workload's policy/cache; never share it across client identities.
// Apply is serialized and must finish backend programming AND trusted persistence
// before returning nil. Sockets/listener netns, identity checks and policy-change
// fencing belong to the agent; the library creates no listener or privileged FD.
type Proxy struct {
	opts     Options
	mu       sync.Mutex
	bindings map[int]map[netip.Addr]Binding
	applied  bool
}

func New(opts Options) (*Proxy, error) {
	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits()
	}
	l := opts.Limits
	if opts.Mode != "include" && opts.Mode != "exclude" || opts.Apply == nil || len(opts.Rules) > l.MaxRules || l.MaxRules <= 0 || l.MaxRules > 64 || l.MaxDomains <= 0 || l.MaxDomains > 64 || l.MaxBindings <= 0 || l.MaxBindings > 4096 || l.MaxRecords <= 0 || l.MaxRecords > 1024 || l.MaxChain <= 0 || l.MaxChain > 32 || l.MaxTTL < time.Second || l.MaxTTL > 24*time.Hour || l.Timeout <= 0 || l.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	host, port, e := net.SplitHostPort(opts.Resolver)
	ip, f := netip.ParseAddr(host)
	n, g := strconv.Atoi(port)
	if e != nil || f != nil || g != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || n < 1 || n > 65535 {
		return nil, ErrInvalid
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Exchange == nil {
		opts.Exchange = Exchange
	}
	rules := make([]Rule, len(opts.Rules))
	for i, r := range opts.Rules {
		if len(r.Domains) > l.MaxDomains || len(r.CIDRs) > 64 || len(r.Ports) > 4096 {
			return nil, ErrInvalid
		}
		rules[i] = Rule{Domains: append([]string(nil), r.Domains...), CIDRs: append([]netip.Prefix(nil), r.CIDRs...), Ports: append([]datapath.Port(nil), r.Ports...)}
		for _, pattern := range r.Domains {
			if !validPattern(pattern) {
				return nil, ErrInvalid
			}
		}
		for _, p := range r.CIDRs {
			if !p.IsValid() || !p.Addr().Is4() {
				return nil, ErrInvalid
			}
		}
		for _, p := range r.Ports {
			if p.Port == 0 || p.Protocol != "TCP" && p.Protocol != "UDP" {
				return nil, ErrInvalid
			}
		}
	}
	opts.Rules = rules
	p := &Proxy{opts: opts, bindings: map[int]map[netip.Addr]Binding{}}
	for _, b := range opts.Restore {
		if b.Rule < 0 || b.Rule >= len(rules) || len(rules[b.Rule].Domains) == 0 || !validAddress(b.Address) || b.ExpiresAt <= 0 || b.Retained != (opts.Mode == "include") {
			return nil, ErrInvalid
		}
		if p.bindings[b.Rule] == nil {
			p.bindings[b.Rule] = map[netip.Addr]Binding{}
		}
		if _, exists := p.bindings[b.Rule][b.Address]; exists {
			return nil, ErrInvalid
		}
		p.bindings[b.Rule][b.Address] = b
	}
	if count(p.bindings) > l.MaxBindings {
		return nil, ErrCapacity
	}
	return p, nil
}
func validPattern(pattern string) bool {
	if len(pattern) > 2 && pattern[:2] == "*." {
		suffix, e := NormalizeName(pattern[2:])
		return e == nil && MatchPattern("probe."+suffix, pattern)
	}
	_, e := NormalizeName(pattern)
	return e == nil
}
func validAddress(a netip.Addr) bool {
	return a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
func count(m map[int]map[netip.Addr]Binding) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}
func clone(m map[int]map[netip.Addr]Binding) map[int]map[netip.Addr]Binding {
	out := map[int]map[netip.Addr]Binding{}
	for rule, values := range m {
		out[rule] = map[netip.Addr]Binding{}
		for addr, b := range values {
			out[rule][addr] = b
		}
	}
	return out
}
func (p *Proxy) expire(m map[int]map[netip.Addr]Binding, now time.Time) {
	if p.opts.Mode == "include" {
		return
	}
	for rule, values := range m {
		for addr, b := range values {
			if b.ExpiresAt <= now.Unix() {
				delete(m[rule], addr)
			}
		}
	}
}
func (p *Proxy) update(m map[int]map[netip.Addr]Binding) Update {
	out := Update{}
	for i, r := range p.opts.Rules {
		prefixes := map[netip.Prefix]bool{}
		for _, cidr := range r.CIDRs {
			prefixes[cidr.Masked()] = true
		}
		for addr, b := range m[i] {
			prefixes[netip.PrefixFrom(addr, 32)] = true
			out.State = append(out.State, b)
		}
		// An unresolved domain-only selector is EMPTY, not an empty-CIDR wildcard.
		if len(r.Domains) > 0 && len(prefixes) == 0 {
			continue
		}
		material := datapath.Rule{Ports: append([]datapath.Port(nil), r.Ports...)}
		for prefix := range prefixes {
			material.CIDRs = append(material.CIDRs, prefix)
		}
		sort.Slice(material.CIDRs, func(i, j int) bool { return material.CIDRs[i].String() < material.CIDRs[j].String() })
		out.Rules = append(out.Rules, material)
	}
	sort.Slice(out.State, func(i, j int) bool {
		if out.State[i].Rule == out.State[j].Rule {
			return out.State[i].Address.Less(out.State[j].Address)
		}
		return out.State[i].Rule < out.State[j].Rule
	})
	return out
}
func (p *Proxy) commit(ctx context.Context, candidate map[int]map[netip.Addr]Binding) error {
	update := p.update(candidate)
	// Validate expanded rule bounds using the shared datapath representation.
	cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("192.0.2.1"), GatewayID: 1, MTU: 1400, Policy: datapath.Policy{Mode: p.opts.Mode, Rules: update.Rules}}
	if cfg.Validate() != nil {
		return ErrCapacity
	}
	if p.opts.Apply(ctx, update) != nil {
		return ErrApply
	}
	p.bindings = candidate
	p.applied = true
	return nil
}

// Sync applies restored/expired state transactionally. Call before listener
// readiness and periodically afterward, especially to withdraw exclude bypasses.
func (p *Proxy) Sync(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	candidate := clone(p.bindings)
	p.expire(candidate, p.opts.Clock())
	return p.commit(ctx, candidate)
}
func (p *Proxy) Snapshot() Update { p.mu.Lock(); defer p.mu.Unlock(); return p.update(p.bindings) }

// Rules returns an independent materialized snapshot; Snapshot also includes
// persisted bindings needed for safe include restoration.
func (p *Proxy) Rules() []datapath.Rule { return p.Snapshot().Rules }

// Exchange retries truncated UDP answers once over TCP using the SAME resolver.
// Agent integrations may inject a namespace/mark-aware ExchangeFunc instead.
func Exchange(ctx context.Context, req *mdns.Msg, resolver, protocol string) (*mdns.Msg, error) {
	if protocol != "udp" && protocol != "tcp" {
		return nil, ErrInvalid
	}
	client := &mdns.Client{Net: protocol, Timeout: 3 * time.Second, Dialer: &net.Dialer{Timeout: 3 * time.Second}}
	answer, _, err := client.ExchangeContext(ctx, req, resolver)
	if err != nil || answer == nil {
		return nil, ErrInvalid
	}
	if answer.Truncated && protocol == "udp" {
		client.Net = "tcp"
		answer, _, err = client.ExchangeContext(ctx, req, resolver)
	}
	if err != nil || answer == nil || answer.Truncated {
		return nil, ErrInvalid
	}
	return answer, nil
}
func (p *Proxy) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	if req == nil || len(req.Question) != 1 || req.Opcode != mdns.OpcodeQuery || req.Question[0].Qclass != mdns.ClassINET {
		p.reject(w, req, mdns.RcodeFormatError)
		return
	}
	name, e := NormalizeName(req.Question[0].Name)
	// Cluster SRV/PTR and other legitimate non-hostname queries pass through; they
	// do not grant domain-derived IPv4 selectors. A questions must be valid names.
	if e != nil && req.Question[0].Qtype == mdns.TypeA {
		p.reject(w, req, mdns.RcodeFormatError)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.opts.Limits.Timeout)
	defer cancel()
	protocol := "udp"
	if w.RemoteAddr() != nil && w.RemoteAddr().Network() == "tcp" {
		protocol = "tcp"
	}
	answer, err := p.opts.Exchange(ctx, req.Copy(), p.opts.Resolver, protocol)
	if err == nil && answer != nil && answer.Truncated && protocol == "udp" {
		answer, err = p.opts.Exchange(ctx, req.Copy(), p.opts.Resolver, "tcp")
	}
	if err != nil || !validTransaction(req, answer, p.opts.Limits.MaxRecords) {
		p.reject(w, req, mdns.RcodeServerFailure)
		return
	}
	if req.Question[0].Qtype != mdns.TypeA {
		answer.Id = req.Id
		_ = w.WriteMsg(answer)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	matching := []int{}
	for i, r := range p.opts.Rules {
		for _, pattern := range r.Domains {
			if MatchPattern(name, pattern) {
				matching = append(matching, i)
				break
			}
		}
	}
	if len(matching) == 0 {
		answer.Id = req.Id
		_ = w.WriteMsg(answer)
		return
	}
	addresses, err := learnable(req, answer, p.opts.Limits.MaxRecords, p.opts.Limits.MaxChain, p.opts.Limits.MaxTTL)
	if err != nil {
		p.reject(w, req, mdns.RcodeServerFailure)
		return
	}
	now := p.opts.Clock()
	candidate := clone(p.bindings)
	p.expire(candidate, now)
	for _, rule := range matching {
		if candidate[rule] == nil {
			candidate[rule] = map[netip.Addr]Binding{}
		}
		for _, record := range addresses {
			expiry := now.Add(record.ttl).Unix()
			if expiry <= now.Unix() {
				p.reject(w, req, mdns.RcodeServerFailure)
				return
			}
			old := candidate[rule][record.addr]
			if old.ExpiresAt > expiry {
				expiry = old.ExpiresAt
			}
			candidate[rule][record.addr] = Binding{Rule: rule, Address: record.addr, ExpiresAt: expiry, Retained: p.opts.Mode == "include"}
		}
	}
	if count(candidate) > p.opts.Limits.MaxBindings {
		p.reject(w, req, mdns.RcodeServerFailure)
		return
	}
	// Negative/no-address answers do not erase still-valid existing bindings.
	if len(addresses) > 0 || !p.applied || p.opts.Mode == "exclude" {
		if err := p.commit(ctx, candidate); err != nil {
			p.reject(w, req, mdns.RcodeServerFailure)
			return
		}
	}
	response := filterMatchedAnswer(req, answer)
	// Cap delivered TTL by BOTH the A/CNAME lifetime and elapsed apply latency.
	ttlCap := p.opts.Limits.MaxTTL
	for _, record := range addresses {
		if record.ttl < ttlCap {
			ttlCap = record.ttl
		}
	}
	responseNow := p.opts.Clock()
	elapsed := responseNow.Sub(now)
	ttlCap -= elapsed
	// Persisted Unix-second deadlines round DOWN. Cap DNS TTL to that actual
	// deadline too, not only the unrounded duration, so an exclude bypass cannot
	// expire before the cache lifetime promised to the workload resolver.
	for _, rule := range matching {
		for _, record := range addresses {
			remaining := time.Unix(candidate[rule][record.addr].ExpiresAt, 0).Sub(responseNow)
			if remaining < ttlCap {
				ttlCap = remaining
			}
		}
	}
	if len(addresses) > 0 && ttlCap < time.Second {
		p.reject(w, req, mdns.RcodeServerFailure)
		return
	}
	seconds := ttlCap / time.Second
	if seconds < 0 || seconds > 86400 {
		p.reject(w, req, mdns.RcodeServerFailure)
		return
	}
	cappedTTL := uint32(seconds) // #nosec G115 -- explicitly bounded to [0,86400] immediately above.
	for _, rr := range response.Answer {
		if len(addresses) > 0 && cappedTTL < rr.Header().Ttl {
			rr.Header().Ttl = cappedTTL
		}
	}
	response.Id = req.Id
	_ = w.WriteMsg(response)
}
func (p *Proxy) reject(w mdns.ResponseWriter, req *mdns.Msg, rcode int) {
	answer := new(mdns.Msg)
	if req != nil {
		answer.SetRcode(req, rcode)
	} else {
		answer.Rcode = rcode
		answer.Response = true
	}
	_ = w.WriteMsg(answer)
}
