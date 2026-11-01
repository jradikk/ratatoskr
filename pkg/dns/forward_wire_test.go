package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// Every listener is loopback-only on an ephemeral port. The test uses no
// resolv.conf/system resolver, cluster, network capability, or external DNS.
func wireServer(t *testing.T, handler mdns.Handler) (string, func()) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	servers := []*mdns.Server{{PacketConn: udp, Net: "udp", Handler: handler},
		{Listener: tcp, Net: "tcp", Handler: handler}}
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(s *mdns.Server) { defer wg.Done(); _ = s.ActivateAndServe() }(server)
	}
	return udp.LocalAddr().String(), func() {
		for _, server := range servers {
			_ = server.Shutdown()
		}
		wg.Wait()
	}
}

func askWire(t *testing.T, addr, protocol, name string) *mdns.Msg {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	answer, _, err := (&mdns.Client{Net: protocol, Timeout: 2 * time.Second}).ExchangeContext(ctx, req, addr)
	if err != nil {
		t.Fatalf("local %s DNS exchange: %v", protocol, err)
	}
	if answer.Id != req.Id || len(answer.Question) != 1 || answer.Question[0].Name != req.Question[0].Name {
		t.Fatal("DNS reply lost query identity")
	}
	return answer
}

func TestWireUDPAndTCPClusterSplitAndExternalFailClose(t *testing.T) {
	var clusterCalls, externalCalls atomic.Int32
	clusterAddr, stopCluster := wireServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		clusterCalls.Add(1)
		if !strings.HasSuffix(strings.ToLower(req.Question[0].Name), ".cluster.local.") &&
			!strings.HasSuffix(req.Question[0].Name, ".in-addr.arpa.") {
			t.Error("external name reached local kube-dns stand-in")
		}
		answer := new(mdns.Msg)
		answer.SetReply(req)
		answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: req.Question[0].Name,
			Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30}, A: net.IPv4(10, 42, 1, 9)}}
		_ = w.WriteMsg(answer)
	}))
	defer stopCluster()
	externalAddr, stopExternal := wireServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		externalCalls.Add(1)
		answer := new(mdns.Msg)
		answer.SetReply(req)
		_ = w.WriteMsg(answer)
	}))
	defer stopExternal()

	var ready atomic.Bool
	f, err := New(Options{ClusterDNS: netip.MustParseAddr("10.43.0.10"),
		UpstreamDNS: netip.MustParseAddr("1.1.1.1"), ClusterDomain: "cluster.local",
		ClusterCIDRs:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")},
		ExternalReady: ready.Load})
	if err != nil {
		t.Fatal(err)
	}
	var targetMu sync.Mutex
	var targets []string
	failUpstream := atomic.Bool{}
	f.exchange = func(ctx context.Context, req *mdns.Msg, addr string, upstream bool, protocol string) (*mdns.Msg, error) {
		targetMu.Lock()
		targets = append(targets, addr+"/"+protocol)
		targetMu.Unlock()
		if upstream {
			if addr != "1.1.1.1:53" {
				return nil, errors.New("wrong upstream")
			}
			if failUpstream.Load() {
				return nil, errors.New("upstream tunnel unavailable")
			}
			// Socket routing to upstream0 is NOT proven by a loopback test.
			return exchange(ctx, req, externalAddr, false, protocol)
		}
		if addr != "10.43.0.10:53" {
			return nil, errors.New("wrong cluster resolver")
		}
		return exchange(ctx, req, clusterAddr, false, protocol)
	}
	front, stopFront := wireServer(t, f)
	defer stopFront()
	for _, protocol := range []string{"udp", "tcp"} {
		for _, name := range []string{"KUBERNETES.default.svc.cluster.local.", "3.2.42.10.in-addr.arpa."} {
			answer := askWire(t, front, protocol, name)
			if answer.Rcode != mdns.RcodeSuccess || len(answer.Answer) != 1 {
				t.Fatalf("cluster %s %s DNS response missing", protocol, name)
			}
		}
		for _, name := range []string{"www.example.invalid.", "8.8.8.8.in-addr.arpa."} {
			if answer := askWire(t, front, protocol, name); answer.Rcode != mdns.RcodeServerFailure {
				t.Fatalf("external %s %s did not fail closed before upstream ready", protocol, name)
			}
		}
	}
	if got := clusterCalls.Load(); got != 4 {
		t.Fatalf("cluster queries got %d, want 4", got)
	}
	if got := externalCalls.Load(); got != 0 {
		t.Fatalf("unhealthy external DNS reached network %d times", got)
	}
	ready.Store(true)
	for _, protocol := range []string{"udp", "tcp"} {
		if answer := askWire(t, front, protocol, "www.example.invalid."); answer.Rcode != mdns.RcodeSuccess {
			t.Fatalf("healthy external %s transport failed", protocol)
		}
	}
	if got := externalCalls.Load(); got != 2 {
		t.Fatalf("external resolver queried %d times, want 2", got)
	}
	failUpstream.Store(true)
	for _, protocol := range []string{"udp", "tcp"} {
		if answer := askWire(t, front, protocol, "www.example.invalid."); answer.Rcode != mdns.RcodeServerFailure {
			t.Fatalf("failed upstream %s did not SERVFAIL", protocol)
		}
		if answer := askWire(t, front, protocol, "kubernetes.default.svc.cluster.local."); answer.Rcode != mdns.RcodeSuccess {
			t.Fatalf("failed upstream also broke cluster DNS/%s", protocol)
		}
	}
	if got := externalCalls.Load(); got != 2 {
		t.Fatalf("failed upstream fell back over network: %d", got)
	}
	targetMu.Lock()
	defer targetMu.Unlock()
	if len(targets) != 10 {
		t.Fatalf("forwarded %d requests, want 10", len(targets))
	}
	for _, target := range targets {
		if target != "10.43.0.10:53/udp" && target != "10.43.0.10:53/tcp" &&
			target != "1.1.1.1:53/udp" && target != "1.1.1.1:53/tcp" {
			t.Fatalf("forwarded DNS to unexpected target %q", target)
		}
	}
}
