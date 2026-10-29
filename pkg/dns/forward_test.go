package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	mdns "github.com/miekg/dns"
)

type memoryWriter struct {
	response *mdns.Msg
	network  string
}

func (w *memoryWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 42, 1, 1), Port: 1053}
}
func (w *memoryWriter) RemoteAddr() net.Addr {
	if w.network == "tcp" {
		return &net.TCPAddr{IP: net.IPv4(10, 42, 1, 8), Port: 1234}
	}
	return &net.UDPAddr{IP: net.IPv4(10, 42, 1, 8), Port: 1234}
}
func (w *memoryWriter) WriteMsg(m *mdns.Msg) error { w.response = m.Copy(); return nil }
func (w *memoryWriter) Write([]byte) (int, error)  { return 0, errors.New("unexpected raw write") }
func (w *memoryWriter) Close() error               { return nil }
func (w *memoryWriter) TsigStatus() error          { return nil }
func (w *memoryWriter) TsigTimersOnly(bool)        {}
func (w *memoryWriter) Hijack()                    {}
func options(ready func() bool) Options {
	return Options{ClusterDNS: netip.MustParseAddr("10.43.0.10"), UpstreamDNS: netip.MustParseAddr("1.1.1.1"), ClusterDomain: "cluster.local", ClusterCIDRs: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}, ExternalReady: ready}
}
func query(f *Forwarder, name, network string) (*memoryWriter, uint16) {
	w := &memoryWriter{network: network}
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	req.Id = 902
	f.ServeDNS(w, req)
	return w, req.Id
}
func TestRoutesClusterAndReverseWithoutVPN(t *testing.T) {
	f, err := New(options(func() bool { return false }))
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	f.exchange = func(ctx context.Context, req *mdns.Msg, address string, upstream bool, network string) (*mdns.Msg, error) {
		called++
		if address != "10.43.0.10:53" || upstream || network != "tcp" {
			t.Fatalf("cluster query escaped: %q %t %s", address, upstream, network)
		}
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp, nil
	}
	for _, name := range []string{"KUBERNETES.default.svc.cluster.local.", "3.2.42.10.in-addr.arpa.", "42.10.in-addr.arpa.", "10.0.43.10.in-addr.arpa."} {
		w, id := query(f, name, "tcp")
		if w.response == nil || w.response.Rcode != mdns.RcodeSuccess || w.response.Id != id {
			t.Fatalf("cluster query failed: %s", name)
		}
	}
	if called != 4 {
		t.Fatal("some cluster queries were not forwarded")
	}
}
func TestExternalFailsClosedAndUsesOnlyUpstream(t *testing.T) {
	ready := false
	f, err := New(options(func() bool { return ready }))
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	f.exchange = func(ctx context.Context, req *mdns.Msg, address string, upstream bool, network string) (*mdns.Msg, error) {
		called++
		if address != "1.1.1.1:53" || !upstream || network != "udp" {
			t.Fatalf("external query bypassed VPN: %q %t %s", address, upstream, network)
		}
		return nil, errors.New("tunnel unavailable")
	}
	for _, name := range []string{"www.example.org.", "evilcluster.local.example.org.", "8.8.8.8.in-addr.arpa."} {
		w, _ := query(f, name, "udp")
		if w.response.Rcode != mdns.RcodeServerFailure {
			t.Fatalf("unhealthy external query did not fail closed: %s", name)
		}
	}
	if called != 0 {
		t.Fatal("upstream socket opened while unhealthy")
	}
	ready = true
	w, _ := query(f, "www.example.org.", "udp")
	if called != 1 || w.response.Rcode != mdns.RcodeServerFailure {
		t.Fatal("failed upstream query used fallback route")
	}
}
func TestRequiresClusterCIDRs(t *testing.T) {
	o := options(func() bool { return true })
	o.ClusterCIDRs = nil
	if _, err := New(o); err == nil {
		t.Fatal("no cluster reverse exclusions allowed")
	}
}
