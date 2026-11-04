//go:build linux && privileged

package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	corev1 "k8s.io/api/core/v1"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/fqdn"
)

// Run this binary in an unshared disposable process netns. Its original/agent
// namespace is only anchored/restored, never routed/programmed; workload and
// resolver are separate disposable namespaces connected without host links.
func TestPrivilegedDomainMarkedTargetDNSCapture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root CAP_SYS_ADMIN/NET_ADMIN")
	}
	if verifiedOwn.Load() != nil {
		t.Skip("anchor already established")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	agentNS, err := netns.Get()
	if errors.Is(err, unix.EPERM) {
		t.Skip("CAP_SYS_ADMIN unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := netns.Set(original); e != nil {
			panic(e)
		}
		_ = agentNS.Close()
	}()
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	anchor, err := validateOwnAnchor(own)
	if err != nil {
		t.Fatal(err)
	}
	verifiedOwn.Store(anchor)
	defer verifiedOwn.Store(nil)
	workload, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer workload.Close()
	peer, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = netns.Set(workload); err != nil {
		t.Fatal(err)
	}
	pair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}, PeerName: "dnspeer"}
	if err = netlink.LinkAdd(pair); err != nil {
		t.Fatal(err)
	}
	peerLink, err := netlink.LinkByName("dnspeer")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetNsFd(peerLink, int(peer)); err != nil {
		t.Fatal(err)
	}
	configure := func(name, ip string) {
		t.Helper()
		link, e := netlink.LinkByName(name)
		if e != nil {
			t.Fatal(e)
		}
		address, e := netlink.ParseAddr(ip)
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.AddrAdd(link, address); e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetUp(link); e != nil {
			t.Fatal(e)
		}
		lo, e := netlink.LinkByName("lo")
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetUp(lo); e != nil {
			t.Fatal(e)
		}
	}
	configure("eth0", "198.18.0.2/30")
	if err = netns.Set(peer); err != nil {
		t.Fatal(err)
	}
	configure("dnspeer", "198.18.0.1/30")
	sources := make(chan string, 4)
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		sources <- host
		m := new(mdns.Msg).SetReply(q)
		rr, _ := mdns.NewRR("example.test. 60 IN A 203.0.113.8")
		m.Answer = []mdns.RR{rr}
		_ = w.WriteMsg(m)
	})
	udp, err := net.ListenPacket("udp4", "198.18.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "198.18.0.1:53")
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	servers := []*mdns.Server{{PacketConn: udp, Net: "udp", Handler: handler}, {Listener: tcp, Net: "tcp", Handler: handler}}
	for _, srv := range servers {
		ready := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(ready) }
		go func(s *mdns.Server) { _ = s.ActivateAndServe() }(srv)
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("resolver start timeout")
		}
	}
	defer func() {
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
	}()
	if err = netns.Set(agentNS); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.FcntlInt(uintptr(workload), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	target := os.NewFile(uintptr(fd), "disposable-domain-workload")
	defer target.Close()
	var inode unix.Stat_t
	if err = unix.Fstat(fd, &inode); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{}
	rt := &domainRuntime{uid: "privileged-domain", netns: target, inode: inode, podIP: netip.MustParseAddr("198.18.0.2"), resolver: netip.MustParseAddr("198.18.0.1")}
	applies := 0
	proxy, err := fqdn.New(fqdn.Options{Mode: "include", Rules: []fqdn.Rule{{Domains: []string{"example.test"}}}, Resolver: "198.18.0.1:53", Apply: func(context.Context, fqdn.Update) error { applies++; return nil }, Exchange: func(ctx context.Context, q *mdns.Msg, resolver, protocol string) (*mdns.Msg, error) {
		result, e := r.exchangeDomain(ctx, rt, q, resolver, protocol)
		if e != nil {
			t.Logf("synthetic forwarding error: %v", e)
		}
		return result, e
	}})
	if err != nil {
		t.Fatal(err)
	}
	var localUDP net.PacketConn
	var localTCP net.Listener
	if err = InNamespace(target, func() error {
		var e error
		localUDP, e = net.ListenPacket("udp4", "127.0.0.1:1053")
		if e != nil {
			return e
		}
		localTCP, e = net.Listen("tcp4", "127.0.0.1:1053")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	proxyServers := []*mdns.Server{{PacketConn: localUDP, Net: "udp", Handler: proxy}, {Listener: localTCP, Net: "tcp", Handler: proxy}}
	for _, srv := range proxyServers {
		ready := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(ready) }
		go func(s *mdns.Server) { _ = s.ActivateAndServe() }(srv)
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("proxy start timeout")
		}
	}
	defer func() {
		for _, srv := range proxyServers {
			_ = srv.Shutdown()
		}
	}()
	if err = InNamespace(target, func() error { return iproute.InstallDNSRedirect(rt.resolver) }); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		var conn net.Conn
		if err = InNamespace(target, func() error {
			var e error
			conn, e = (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), protocol+"4", "198.18.0.1:53")
			return e
		}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		answer, _, e := (&mdns.Client{Net: protocol, Timeout: 3 * time.Second}).ExchangeWithConnContext(ctx, new(mdns.Msg).SetQuestion("example.test.", mdns.TypeA), &mdns.Conn{Conn: conn})
		cancel()
		_ = conn.Close()
		if e != nil || answer.Rcode != mdns.RcodeSuccess || len(answer.Answer) != 1 {
			t.Fatalf("captured %s query failed: err=%v code=%d answers=%d applies=%d", protocol, e, answer.Rcode, len(answer.Answer), applies)
		}
		select {
		case source := <-sources:
			if source != "198.18.0.2" {
				t.Fatal("DNS forwarding escaped target PodIP")
			}
		case <-time.After(time.Second):
			t.Fatal("marked DNS did not reach resolver")
		}
	}
	if applies != 2 {
		t.Fatal("UDP/TCP queries bypassed application barrier or mark exemption recursed")
	}
	for _, srv := range proxyServers {
		_ = srv.Shutdown()
	}
	if err = InNamespace(target, func() error { return iproute.RemoveDNSRedirect(rt.resolver) }); err != nil {
		t.Fatal(err)
	}
	runtimeAgent, p, gw, pol, cfg, _, _, _ := domainFixture(t, "include")
	var svc corev1.Service
	if err = runtimeAgent.Client.Get(context.Background(), client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name + "-dns"}, &svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.ClusterIP = rt.resolver.String()
	if err = runtimeAgent.Client.Update(context.Background(), &svc); err != nil {
		t.Fatal(err)
	}
	p.Spec.DNSConfig.Nameservers = []string{rt.resolver.String()}
	p.Status.PodIP = rt.podIP.String()
	cfg.PodIP = rt.podIP
	runtimeAgent.domainOps = nil
	realOps := runtimeAgent.domainOperations()
	// Startup still runs real target entry, loopback binds, nft install/verify,
	// optimistic API annotation patch and readiness marker publication. Only CRI
	// recheck is fake because this fixture owns disposable non-CRI namespaces.
	realOps.recheck = func(context.Context, cri.RuntimeServiceClient, sandboxProof, *os.File) error { return nil }
	runtimeAgent.domainOps = &realOps
	lock := runtimeAgent.domainLock(string(p.UID))
	lock.Lock()
	err = runtimeAgent.startDomain(context.Background(), p, gw, pol, cfg, target, sandboxProof{inode: inode, pidfd: -1}, "iproute")
	lock.Unlock()
	if err != nil {
		t.Fatalf("actual-kernel startup failed: %v", err)
	}
	runtimeAgent.closeDomains()
	if err = checkThreadOwn(); err != nil {
		t.Fatal("caller thread not restored to agent netns")
	}
}
