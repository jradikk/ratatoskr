package fqdn

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

type writer struct {
	messages []*mdns.Msg
	before   func(*mdns.Msg)
}

func (w *writer) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1053} }
func (w *writer) RemoteAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30000} }
func (w *writer) WriteMsg(m *mdns.Msg) error {
	if w.before != nil {
		w.before(m)
	}
	w.messages = append(w.messages, m.Copy())
	return nil
}
func (*writer) Write(b []byte) (int, error)      { return len(b), nil }
func (*writer) Close() error                     { return nil }
func (*writer) TsigStatus() error                { return nil }
func (*writer) TsigTimersOnly(bool)              {}
func (*writer) Hijack()                          {}
func question(name string, typ uint16) *mdns.Msg { return new(mdns.Msg).SetQuestion(name, typ) }
func response(req *mdns.Msg, rrs ...string) *mdns.Msg {
	m := new(mdns.Msg).SetReply(req)
	for _, raw := range rrs {
		rr, e := mdns.NewRR(raw)
		if e != nil {
			panic("invalid synthetic RR fixture")
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}
func opts(mode string, now *time.Time, apply func(context.Context, Update) error) Options {
	return Options{Mode: mode, Rules: []Rule{{Domains: []string{"example.test"}, Ports: []datapath.Port{{Protocol: "TCP", Port: 443}}}}, Resolver: "192.0.2.53:53", Apply: apply, Clock: func() time.Time { return *now }}
}
func mustProxy(t *testing.T, o Options) *Proxy {
	t.Helper()
	p, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func answerCode(t *testing.T, p *Proxy, req *mdns.Msg, code int) {
	t.Helper()
	w := &writer{}
	p.ServeDNS(w, req)
	if len(w.messages) != 1 || w.messages[0].Rcode != code {
		t.Fatalf("DNS response code incorrect; messages=%d", len(w.messages))
	}
}
func TestNames(t *testing.T) {
	for _, tc := range []struct {
		name, pattern string
		want          bool
	}{{"WWW.Example.COM.", "*.example.com", true}, {"a.b.example.com", "*.example.com", true}, {"example.com", "*.example.com", false}, {"notexample.com", "*.example.com", false}, {"a.com", "*.com", false}, {"x.example.com", "x.*.com", false}, {"EXAMPLE.COM.", "example.com", true}, {"192.0.2.1", "192.0.2.1", false}, {"x..example.com", "*.example.com", false}} {
		if MatchPattern(tc.name, tc.pattern) != tc.want {
			t.Fatal("name/pattern contract mismatch")
		}
	}
}
func TestTransactionalLearnBeforeReplyPreservesCIDROrPorts(t *testing.T) {
	now := time.Unix(1000, 0)
	applied := false
	var update Update
	o := opts("include", &now, func(_ context.Context, u Update) error { applied = true; update = u; return nil })
	o.Rules[0].CIDRs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 60 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	w := &writer{before: func(m *mdns.Msg) {
		if !applied || m.Rcode != mdns.RcodeSuccess {
			t.Fatal("answer escaped application barrier")
		}
	}}
	p.ServeDNS(w, question("example.test.", mdns.TypeA))
	if len(update.Rules) != 1 || len(update.Rules[0].CIDRs) != 2 || !reflect.DeepEqual(update.Rules[0].Ports, o.Rules[0].Ports) || len(update.State) != 1 || !update.State[0].Retained {
		t.Fatal("CIDR OR domain /32 or qualified ports lost")
	}
	if update.State[0].ExpiresAt != 1060 {
		t.Fatal("incorrect expiry")
	}
}
func TestFailedApplyRetainsOldSnapshotAndServfail(t *testing.T) {
	now := time.Unix(1000, 0)
	fail := false
	ip := "203.0.113.8"
	o := opts("include", &now, func(context.Context, Update) error {
		if fail {
			return errors.New("synthetic private marker")
		}
		return nil
	})
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 60 IN A "+ip), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	before := p.Snapshot()
	fail = true
	ip = "203.0.113.9"
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeServerFailure)
	if !reflect.DeepEqual(before, p.Snapshot()) {
		t.Fatal("failed apply committed candidate state")
	}
}
func TestCNAMEChainMinimumTTLAndAnswerOnly(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		m := response(r, "example.test. 12 IN CNAME edge.example.test.", "edge.example.test. 60 IN A 203.0.113.8", "unrelated.test. 60 IN A 203.0.113.99")
		rr, _ := mdns.NewRR("additional.test. 60 IN A 203.0.113.98")
		m.Extra = []mdns.RR{rr}
		return m, nil
	}
	p := mustProxy(t, o)
	w := &writer{}
	p.ServeDNS(w, question("example.test.", mdns.TypeA))
	state := p.Snapshot().State
	if len(state) != 1 || state[0].Address.String() != "203.0.113.8" || state[0].ExpiresAt != 1012 {
		t.Fatal("CNAME TTL or poison filtering failed")
	}
	for _, rr := range w.messages[0].Answer {
		if rr.Header().Ttl > 12 {
			t.Fatal("answer TTL exceeds routing lifetime")
		}
	}
}
func TestMalformedCyclesZeroTTLAndAmbiguousAnswerReject(t *testing.T) {
	cases := [][]string{{"example.test. 0 IN A 203.0.113.8"}, {"example.test. 30 IN CNAME edge.test.", "edge.test. 0 IN A 203.0.113.8"}, {"example.test. 30 IN CNAME edge.test.", "edge.test. 30 IN CNAME example.test."}, {"example.test. 30 IN CNAME edge.test.", "example.test. 30 IN CNAME other.test."}, {"example.test. 30 IN CNAME edge.test.", "example.test. 30 IN A 203.0.113.8"}, {"example.test. 30 IN A 127.0.0.1"}}
	for i, rrs := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			now := time.Unix(1000, 0)
			calls := 0
			o := opts("include", &now, func(context.Context, Update) error { calls++; return nil })
			o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
				return response(r, rrs...), nil
			}
			p := mustProxy(t, o)
			answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeServerFailure)
			if calls != 0 || len(p.Snapshot().State) != 0 {
				t.Fatal("invalid answer accepted")
			}
		})
	}
}
func TestIncludeRetainsExpiredProtectAndExcludeWithdraws(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Unix(1000, 0)
			o := opts(mode, &now, func(context.Context, Update) error { return nil })
			o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
				return response(r, "example.test. 10 IN A 203.0.113.8"), nil
			}
			p := mustProxy(t, o)
			answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
			now = now.Add(11 * time.Second)
			if e := p.Sync(context.Background()); e != nil {
				t.Fatal(e)
			}
			u := p.Snapshot()
			if mode == "include" {
				if len(u.State) != 1 || len(u.Rules) != 1 {
					t.Fatal("include protection expired into direct egress")
				}
			} else if len(u.State) != 0 || len(u.Rules) != 0 {
				t.Fatal("expired exclude bypass retained")
			}
		})
	}
}
func TestIncludeCapacityNeverEvictsProtection(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Limits = DefaultLimits()
	o.Limits.MaxBindings = 1
	ip := "203.0.113.8"
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 1 IN A "+ip), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	before := p.Snapshot()
	now = now.Add(time.Hour)
	ip = "203.0.113.9"
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeServerFailure)
	if !reflect.DeepEqual(before, p.Snapshot()) {
		t.Fatal("capacity evicted include protection")
	}
}
func TestDuplicateAUsesMinimumTTLAndSingleBinding(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 60 IN A 203.0.113.8", "example.test. 5 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	if s := p.Snapshot().State; len(s) != 1 || s[0].ExpiresAt != 1005 {
		t.Fatal("duplicate TTL normalization incorrect")
	}
}
func TestNegativeAnswersPreserveUnexpiredBindings(t *testing.T) {
	now := time.Unix(1000, 0)
	negative := false
	o := opts("exclude", &now, func(context.Context, Update) error { return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		m := response(r, "example.test. 60 IN A 203.0.113.8")
		if negative {
			m.Answer = nil
			m.Rcode = mdns.RcodeNameError
		}
		return m, nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	before := p.Snapshot()
	negative = true
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeNameError)
	if !reflect.DeepEqual(before, p.Snapshot()) {
		t.Fatal("negative answer erased prior unexpired rules")
	}
}
func TestInjectedUDPTruncationRetriesTCPBeforeApplication(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := []string{}
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, protocol string) (*mdns.Msg, error) {
		calls = append(calls, protocol)
		m := response(r, "example.test. 60 IN A 203.0.113.8")
		m.Truncated = protocol == "udp"
		return m, nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	if !reflect.DeepEqual(calls, []string{"udp", "tcp"}) {
		t.Fatal("truncated UDP was not retried over TCP")
	}
}
func TestAAAAUnchangedNoLearning(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	o := opts("include", &now, func(context.Context, Update) error { calls++; return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 60 IN AAAA 2001:db8::1"), nil
	}
	p := mustProxy(t, o)
	w := &writer{}
	p.ServeDNS(w, question("example.test.", mdns.TypeAAAA))
	if calls != 0 || len(p.Snapshot().State) != 0 || len(w.messages[0].Answer) != 1 {
		t.Fatal("AAAA modified or learned")
	}
}
func TestSnapshotRestoreNoSharedClientsAndUnresolvedRuleOmitted(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	p := mustProxy(t, o)
	if len(p.Snapshot().Rules) != 0 {
		t.Fatal("unresolved domain-only rule became wildcard")
	}
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 1 IN A 203.0.113.8"), nil
	}
	p = mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	raw, e := json.Marshal(p.Snapshot().State)
	if e != nil {
		t.Fatal(e)
	}
	var bindings []Binding
	if e = json.Unmarshal(raw, &bindings); e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Hour)
	o.Restore = bindings
	restored := mustProxy(t, o)
	if e = restored.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(p.Snapshot(), restored.Snapshot()) {
		t.Fatal("include retained snapshot not restored")
	}
	fresh := mustProxy(t, opts("include", &now, func(context.Context, Update) error { return nil }))
	if len(fresh.Snapshot().State) != 0 {
		t.Fatal("workloads share cache")
	}
}
func TestElapsedApplicationCapsTTLOrReturnsSERVFAIL(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { now = now.Add(11 * time.Second); return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 10 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeServerFailure)
	if len(p.Snapshot().State) != 1 {
		t.Fatal("successful retained protection unexpectedly discarded")
	}
}

func TestRestoreRejectsInvalidAndDuplicateBindings(t *testing.T) {
	now := time.Unix(1000, 0)
	valid := Binding{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 1060, Retained: true}
	cases := []Binding{valid, valid, valid, valid, valid, valid}
	cases[0].Rule = -1
	cases[1].Rule = 64
	cases[2].Address = netip.MustParseAddr("169.254.1.1")
	cases[3].Address = netip.MustParseAddr("2001:db8::1")
	cases[4].ExpiresAt = 0
	cases[5].Retained = false
	for _, b := range cases {
		o := opts("include", &now, func(context.Context, Update) error { return nil })
		o.Restore = []Binding{b}
		if _, e := New(o); e == nil {
			t.Fatal("invalid persisted state accepted")
		}
	}
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Restore = []Binding{valid, valid}
	if _, e := New(o); e == nil {
		t.Fatal("duplicate persisted state accepted")
	}
}
func TestPerRuleCacheAddressPortIsolation(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Rules = append(o.Rules, Rule{Domains: []string{"other.test"}, Ports: []datapath.Port{{Protocol: "UDP", Port: 53}}})
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, r.Question[0].Name+" 60 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	if len(p.Rules()) != 1 || p.Rules()[0].Ports[0].Port != 443 {
		t.Fatal("learned address crossed unmatched rule ports")
	}
	answerCode(t, p, question("other.test.", mdns.TypeA), mdns.RcodeSuccess)
	if len(p.Snapshot().State) != 2 || len(p.Rules()) != 2 {
		t.Fatal("shared address did not retain independent rule qualification")
	}
}
func TestTTLUpperCapAndApplyExpiryRollback(t *testing.T) {
	now := time.Unix(1000, 0)
	fail := false
	o := opts("exclude", &now, func(context.Context, Update) error {
		if fail {
			return ErrApply
		}
		return nil
	})
	o.Limits = DefaultLimits()
	o.Limits.MaxTTL = 20 * time.Second
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 3600 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	w := &writer{}
	p.ServeDNS(w, question("example.test.", mdns.TypeA))
	if w.messages[0].Answer[0].Header().Ttl != 20 || p.Snapshot().State[0].ExpiresAt != 1020 {
		t.Fatal("TTL not capped to bounded policy cache")
	}
	before := p.Snapshot()
	now = now.Add(21 * time.Second)
	fail = true
	if p.Sync(context.Background()) == nil {
		t.Fatal("expired bypass apply failure ignored")
	}
	if !reflect.DeepEqual(before, p.Snapshot()) {
		t.Fatal("expiry failure committed un-applied snapshot")
	}
}
func TestOriginalRuleIndexAfterUnresolvedRules(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Rules = []Rule{{Domains: []string{"never.test"}}, {Domains: []string{"example.test"}}}
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 60 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeSuccess)
	if len(p.Rules()) != 1 || p.Snapshot().State[0].Rule != 1 {
		t.Fatal("original rule index shifted by omission")
	}
}
func TestMismatchResponseAndRepeatedTCFailClosed(t *testing.T) {
	for _, tc := range []string{"ID", "question", "TCP truncated"} {
		t.Run(tc, func(t *testing.T) {
			now := time.Unix(1000, 0)
			calls := 0
			o := opts("include", &now, func(context.Context, Update) error { calls++; return nil })
			o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
				m := response(r, "example.test. 60 IN A 203.0.113.8")
				switch tc {
				case "ID":
					m.Id++
				case "question":
					m.Question[0].Name = "poison.test."
				default:
					m.Truncated = true
				}
				return m, nil
			}
			p := mustProxy(t, o)
			answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeServerFailure)
			if calls != 0 {
				t.Fatal("bad DNS transaction reached privileged callback")
			}
		})
	}
}

func TestExchangeRetriesUDPTruncationAtSameLocalResolver(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpStarted := make(chan struct{})
	tcpStarted := make(chan struct{})
	udpServer := &mdns.Server{PacketConn: udp, Net: "udp", NotifyStartedFunc: func() { close(udpStarted) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) { m := response(r); m.Truncated = true; _ = w.WriteMsg(m) })}
	tcpServer := &mdns.Server{Listener: tcp, Net: "tcp", NotifyStartedFunc: func() { close(tcpStarted) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		_ = w.WriteMsg(response(r, "example.test. 60 IN A 203.0.113.8"))
	})}
	doneUDP := make(chan error, 1)
	doneTCP := make(chan error, 1)
	go func() { doneUDP <- udpServer.ActivateAndServe() }()
	go func() { doneTCP <- tcpServer.ActivateAndServe() }()
	defer func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
		if err := <-doneUDP; err != nil {
			t.Error("fake UDP resolver failed")
		}
		if err := <-doneTCP; err != nil {
			t.Error("fake TCP resolver failed")
		}
	}()
	for _, started := range []chan struct{}{udpStarted, tcpStarted} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("fake local resolver startup timeout")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	answer, err := Exchange(ctx, question("example.test.", mdns.TypeA), tcp.Addr().String(), "udp")
	if err != nil || answer.Truncated || len(answer.Answer) != 1 {
		t.Fatal("real UDP/TCP exchange did not retry truncation")
	}
}
func TestMatchedCNAMEWithoutReachableARejectsBeforeFollowupLeak(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { t.Fatal("incomplete chain must not apply"); return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 60 IN CNAME unselected.other.test."), nil
	}
	p := mustProxy(t, o)
	answerCode(t, p, question("example.test.", mdns.TypeA), mdns.RcodeServerFailure)
}

func TestFractionalUnixExpiryCannotOutliveDeliveredTTL(t *testing.T) {
	now := time.Unix(1000, 900000000)
	o := opts("exclude", &now, func(context.Context, Update) error { return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		return response(r, "example.test. 10 IN A 203.0.113.8"), nil
	}
	p := mustProxy(t, o)
	w := &writer{}
	p.ServeDNS(w, question("example.test.", mdns.TypeA))
	if len(w.messages) != 1 || w.messages[0].Rcode != mdns.RcodeSuccess {
		t.Fatal("unexpected fractional-lifetime response")
	}
	ttl := w.messages[0].Answer[0].Header().Ttl
	expiry := p.Snapshot().State[0].ExpiresAt
	if now.Add(time.Duration(ttl) * time.Second).After(time.Unix(expiry, 0)) {
		t.Fatal("DNS promised cache lifetime exceeds applied binding expiry")
	}
}
func TestMatchedResponseStripsUnprogrammedResolverCacheRecords(t *testing.T) {
	now := time.Unix(1000, 0)
	o := opts("include", &now, func(context.Context, Update) error { return nil })
	o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
		m := response(r, "example.test. 60 IN A 203.0.113.8", "unrelated.test. 60 IN A 203.0.113.99")
		rr, _ := mdns.NewRR("example.test. 60 IN A 203.0.113.98")
		m.Extra = []mdns.RR{rr}
		m.Ns = []mdns.RR{rr}
		return m, nil
	}
	p := mustProxy(t, o)
	w := &writer{}
	p.ServeDNS(w, question("example.test.", mdns.TypeA))
	m := w.messages[0]
	if len(m.Answer) != 1 || len(m.Ns) != 0 || len(m.Extra) != 0 || len(p.Snapshot().State) != 1 {
		t.Fatal("unprogrammed cached address escaped matched DNS barrier")
	}
}
func TestUnmatchedAndAAAATransactionMismatchReject(t *testing.T) {
	for _, typ := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		now := time.Unix(1000, 0)
		o := opts("include", &now, func(context.Context, Update) error { return nil })
		o.Exchange = func(_ context.Context, r *mdns.Msg, _ string, _ string) (*mdns.Msg, error) {
			m := response(r)
			m.Id++
			return m, nil
		}
		p := mustProxy(t, o)
		answerCode(t, p, question("unmatched.test.", typ), mdns.RcodeServerFailure)
	}
}

func TestSyncUnchangedEmptyIncludeExcludeApplyOnce(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Unix(1000, 0)
			calls := 0
			o := opts(mode, &now, func(context.Context, Update) error { calls++; return nil })
			p := mustProxy(t, o)
			for i := 0; i < 5; i++ {
				if err := p.Sync(context.Background()); err != nil {
					t.Fatal(err)
				}
				now = now.Add(time.Second)
			}
			if calls != 1 {
				t.Fatal("unchanged empty state reapplied")
			}
		})
	}
}
func TestSyncRestoredStateRequiresOneInitialCommit(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	o := opts("include", &now, func(context.Context, Update) error { calls++; return nil })
	o.Restore = []Binding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 1, Retained: true}}
	p := mustProxy(t, o)
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(p.Snapshot().State) != 1 {
		t.Fatal("restored include state initial/unchanged commit incorrect")
	}
}
func TestSyncExpiredExcludeAppliesWithdrawalOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	o := opts("exclude", &now, func(context.Context, Update) error { calls++; return nil })
	o.Restore = []Binding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 1002, Retained: false}}
	p := mustProxy(t, o)
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Second)
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(p.Snapshot().State) != 0 {
		t.Fatal("expiry withdrawal skipped or repeatedly committed")
	}
}
func TestSyncFailedInitialCommitRetriesUnchangedState(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	o := opts("include", &now, func(context.Context, Update) error {
		calls++
		if calls == 1 {
			return ErrApply
		}
		return nil
	})
	p := mustProxy(t, o)
	if err := p.Sync(context.Background()); err == nil {
		t.Fatal("failed apply not returned")
	}
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("failed unchanged initial commit was not retried")
	}
}
