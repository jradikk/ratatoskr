//go:build linux && privileged

package dns

import (
	"context"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// One disposable pair of netns and a veth: no host addresses/routes, DNS,
// external resolver, cluster, sysctl, or production process are modified.
// Privileged component target already authorizes netns/netlink operations.
func TestPrivilegedExternalDNSSocketOnlyUpstream(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("privileged DNS test requires root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	gwNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(orig); e != nil {
			t.Errorf("restore netns: %v", e)
		}
		_ = gwNS.Close()
	}()
	upNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer upNS.Close()
	if err = netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	gw, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	if err = gw.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: datapath.UpstreamDevice}, PeerName: "up-peer"}); err != nil {
		t.Fatal(err)
	}
	up, err := gw.LinkByName(datapath.UpstreamDevice)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := gw.LinkByName("up-peer")
	if err != nil {
		t.Fatal(err)
	}
	setAddr := func(h *netlink.Handle, link netlink.Link, address string) {
		t.Helper()
		a, e := netlink.ParseAddr(address)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.AddrAdd(link, a); e != nil {
			t.Fatal(e)
		}
		if e = h.LinkSetUp(link); e != nil {
			t.Fatal(e)
		}
	}
	setAddr(gw, up, "198.19.0.1/30")
	if err = gw.LinkSetNsFd(peer, int(upNS)); err != nil {
		t.Fatal(err)
	}
	// A foreign main-table route for the same destination must not be used by
	// marked, upstream0-bound sockets. Its dummy interface cannot deliver DNS.
	if err = gw.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}); err != nil {
		t.Fatal(err)
	}
	eth, err := gw.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err = gw.LinkSetUp(eth); err != nil {
		t.Fatal(err)
	}
	dest := net.ParseIP("198.19.0.2")
	if err = gw.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: &net.IPNet{IP: dest, Mask: net.CIDRMask(32, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err = gw.RouteAdd(&netlink.Route{LinkIndex: up.Attrs().Index, Table: datapath.GatewayTable,
		Dst: &net.IPNet{IP: dest, Mask: net.CIDRMask(32, 32)}}); err != nil {
		t.Fatal(err)
	}
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = datapath.GatewayTable
	rule.Mark = datapath.ProbeMark
	mask := datapath.MarkMask
	rule.Mask = &mask
	rule.Priority = datapath.RulePriority
	if err = gw.RuleAdd(rule); err != nil {
		t.Fatal(err)
	}
	loop, err := gw.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = gw.LinkSetUp(loop); err != nil {
		t.Fatal(err)
	}
	clusterUDP, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	clusterTCP, err := net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		clusterUDP.Close()
		t.Fatal(err)
	}
	var clusterCalls atomic.Int32
	cluster := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		clusterCalls.Add(1)
		m := new(mdns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})
	cServers := []*mdns.Server{{PacketConn: clusterUDP, Net: "udp", Handler: cluster}, {Listener: clusterTCP, Net: "tcp", Handler: cluster}}
	for _, srv := range cServers {
		go func(s *mdns.Server) { _ = s.ActivateAndServe() }(srv)
	}
	defer func() {
		for _, srv := range cServers {
			_ = srv.Shutdown()
		}
	}()
	if err = netns.Set(upNS); err != nil {
		t.Fatal(err)
	}
	uh, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer uh.Close()
	upPeer, err := uh.LinkByName("up-peer")
	if err != nil {
		t.Fatal(err)
	}
	setAddr(uh, upPeer, "198.19.0.2/30")
	upLoop, err := uh.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = uh.LinkSetUp(upLoop); err != nil {
		t.Fatal(err)
	}
	upstreamUDP, err := net.ListenPacket("udp4", "198.19.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	upstreamTCP, err := net.Listen("tcp4", "198.19.0.2:53")
	if err != nil {
		upstreamUDP.Close()
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	upstream := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		upstreamCalls.Add(1)
		m := new(mdns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})
	servers := []*mdns.Server{{PacketConn: upstreamUDP, Net: "udp", Handler: upstream}, {Listener: upstreamTCP, Net: "tcp", Handler: upstream}}
	for _, srv := range servers {
		go func(s *mdns.Server) { _ = s.ActivateAndServe() }(srv)
	}
	defer func() {
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
	}()
	if err = netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		req := new(mdns.Msg)
		req.SetQuestion("test.example.invalid.", mdns.TypeA)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		reply, e := exchange(ctx, req, net.JoinHostPort(dest.String(), "53"), true, protocol)
		cancel()
		if e != nil || reply == nil || reply.Rcode != mdns.RcodeSuccess {
			t.Fatalf("upstream0 marked %s DNS: %v", protocol, e)
		}
		clusterReq := new(mdns.Msg)
		clusterReq.SetQuestion("kubernetes.default.svc.cluster.local.", mdns.TypeA)
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		answer, e := exchange(ctx, clusterReq, "127.0.0.1:53", false, protocol)
		cancel()
		if e != nil || answer == nil || answer.Rcode != mdns.RcodeSuccess {
			t.Fatalf("cluster %s DNS: %v", protocol, e)
		}
	}
	if clusterCalls.Load() != 2 || upstreamCalls.Load() != 2 {
		t.Fatalf("DNS queries crossed resolver boundary: cluster=%d upstream=%d", clusterCalls.Load(), upstreamCalls.Load())
	}
	// Remove only the synthetic upstream link: external DNS must not fall back
	// to the foreign eth0 route, while cluster names still resolve over lo.
	if err = gw.LinkDel(up); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		req := new(mdns.Msg)
		req.SetQuestion("test.example.invalid.", mdns.TypeA)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		answer, e := exchange(ctx, req, net.JoinHostPort(dest.String(), "53"), true, protocol)
		cancel()
		if e == nil || answer != nil {
			t.Fatalf("external %s silently fell back after upstream0 deletion", protocol)
		}
		clusterReq := new(mdns.Msg)
		clusterReq.SetQuestion("kubernetes.default.svc.cluster.local.", mdns.TypeA)
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		answer, e = exchange(ctx, clusterReq, "127.0.0.1:53", false, protocol)
		cancel()
		if e != nil || answer == nil {
			t.Fatalf("cluster %s DNS failed after upstream loss: %v", protocol, e)
		}
	}
	if clusterCalls.Load() != 4 || upstreamCalls.Load() != 2 {
		t.Fatalf("upstream failure leaked DNS to cluster: cluster=%d upstream=%d", clusterCalls.Load(), upstreamCalls.Load())
	}
}
