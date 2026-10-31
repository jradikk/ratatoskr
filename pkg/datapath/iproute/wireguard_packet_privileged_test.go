//go:build linux && privileged

package iproute

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/wireguard"
)

// This is a low-level two-netns packet metadata probe, not a cluster/e2e test.
// It compares INPUT nft drop counters on plain eth0 vs authenticated WG
// delivery of identically addressed UDP6081 packets.
func TestPrivilegedWireGuardIngressIdentity(t *testing.T) {
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
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = gwNS.Close()
	}()
	gw, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}, PeerName: "peer0"}
	if err := gw.h.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	gatewayIP := netip.MustParseAddr("10.42.2.4")
	clientIP := netip.MustParseAddr("10.42.2.8")
	gl, err := gw.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	ga, err := netlink.ParseAddr("10.42.2.4/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.h.AddrAdd(gl, ga); err != nil {
		t.Fatal(err)
	}
	if err := gw.h.LinkSetUp(gl); err != nil {
		t.Fatal(err)
	}
	conf := datapath.GatewayConfig{PodIP: gatewayIP, GatewayID: 7, MTU: 1320, Encryption: "wireguard", WireGuardPort: 51820, Clients: []netip.Addr{clientIP}}
	if err := gw.ApplyGateway(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	gwPub, err := gw.WireGuardPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := gw.h.LinkByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	clientNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = clientNS.Close()
	}()
	if err := netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	if err := gw.h.LinkSetNsFd(peer, int(clientNS)); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cl, err := client.h.LinkByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.h.LinkSetName(cl, "eth0"); err != nil {
		t.Fatal(err)
	}
	cl, err = client.h.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := netlink.ParseAddr("10.42.2.8/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.h.AddrAdd(cl, ca); err != nil {
		t.Fatal(err)
	}
	if err := client.h.LinkSetUp(cl); err != nil {
		t.Fatal(err)
	}
	if _, err := wireguard.Ensure(client.h, datapath.WireGuardDevice, 51821, datapath.WireGuardMark); err != nil {
		t.Fatal(err)
	}
	clientPub, err := client.WireGuardPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(gwNS); err != nil {
		t.Fatal(err)
	}
	if err := gw.RegisterPeer(context.Background(), gatewayIP, clientIP, clientPub); err != nil {
		t.Fatal(err)
	}
	// Test-only nft observer counts authenticated UDP6081 at INPUT on rtkwg0;
	// without this, WG ReceiveBytes alone would not prove Geneve reaches INPUT.
	observer := gw.nft()
	ot := observer.AddTable(&nftables.Table{Name: "ratatoskr_probe", Family: nftables.TableFamilyINet})
	oc := observer.AddChain(&nftables.Chain{Name: "wg_input", Table: ot, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityMangle})
	observer.AddRule(&nftables.Rule{Table: ot, Chain: oc, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(datapath.WireGuardDevice), 0)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x17, 0xc1}},
		&expr.Counter{},
	}})
	if err := observer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	if err := wireguard.ClientPeer(datapath.WireGuardDevice, gatewayIP, gwPub, 51820); err != nil {
		t.Fatal(err)
	}
	if err := client.wireguardRoutes(clientIP, gatewayIP, true); err != nil {
		t.Fatal(err)
	}
	// Minimal valid GENEVE/TEB with Ethernet and inner IPv4 source equal to
	// the authorized client; outer source is fixed by client socket PodIP.
	// nft sees the UDP header before Geneve removes it; tc sees tunnel metadata.
	innerIP := []byte{0x45, 0, 0, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 10, 42, 2, 8, 10, 42, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0}
	payload := append([]byte{0, 0, 0x65, 0x58, 0, 0, 7, 0}, append([]byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 3, 0x08, 0}, innerIP...)...)
	send := func(bypass bool) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.42.2.8")})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if bypass {
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var serr error
			err = raw.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(datapath.WireGuardMark))
			})
			if err != nil {
				t.Fatal(err)
			}
			if serr != nil {
				t.Fatal(serr)
			}
		}
		if _, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP("10.42.2.4"), Port: datapath.GenevePort}); err != nil {
			t.Fatal(err)
		}
	}
	inputDrops := func() uint64 {
		if err := netns.Set(gwNS); err != nil {
			t.Fatal(err)
		}
		nft := gw.nft()
		chains, err := nft.ListChains()
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range chains {
			if ch.Table.Name == "ratatoskr_wg" && ch.Name == "input" {
				rules, err := nft.GetRules(ch.Table, ch)
				if err != nil {
					t.Fatal(err)
				}
				if len(rules) != 1 {
					t.Fatal("missing ingress guard")
				}
				for _, ex := range rules[0].Exprs {
					if c, ok := ex.(*expr.Counter); ok {
						return c.Packets
					}
				}
			}
		}
		t.Fatal("no input guard counter")
		return 0
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	send(true)
	deadline := time.Now().Add(2 * time.Second)
	for inputDrops() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := inputDrops(); got == 0 {
		t.Fatal("forged plaintext UDP6081 on eth0 was not dropped")
	}
	before := inputDrops()
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	send(false)
	wgClient, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer wgClient.Close()
	deadline = time.Now().Add(2 * time.Second)
	var authenticated bool
	for time.Now().Before(deadline) {
		if err := netns.Set(gwNS); err != nil {
			t.Fatal(err)
		}
		d, err := wgClient.Device(datapath.WireGuardDevice)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Peers) == 1 && d.Peers[0].ReceiveBytes > 0 {
			authenticated = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !authenticated {
		t.Fatal("authenticated WG packet never reached gateway")
	}
	if got := inputDrops(); got != before {
		t.Fatalf("WG packet matched plaintext eth0 guard: before=%d after=%d", before, got)
	}
	probeConn := gw.nft()
	probeRules, err := probeConn.GetRules(ot, oc)
	if err != nil || len(probeRules) != 1 {
		t.Fatalf("missing authenticated WG input observer: %v %v", probeRules, err)
	}
	var authenticatedInputs uint64
	for _, ex := range probeRules[0].Exprs {
		if ct, ok := ex.(*expr.Counter); ok {
			authenticatedInputs = ct.Packets
		}
	}
	if authenticatedInputs == 0 {
		t.Fatal("decrypted UDP6081 never entered input with WG ingress identity")
	}
	// Existing verifier remains attached to gnv0, with outer and inner source
	// + tunnel VNI constraints, independently of the input nft iif guard.
	gnv, err := gw.h.LinkByName(datapath.GatewayDevice)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := gw.h.FilterList(gnv, netlink.MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range fs {
		if flower, ok := f.(*netlink.Flower); ok && flower.SrcIP.Equal(net.ParseIP(clientIP.String())) && flower.EncSrcIP.Equal(net.ParseIP(clientIP.String())) && flower.EncKeyId == 7 {
			found = true
		}
	}
	if !found {
		t.Fatal("outer/inner source/VNI GENEVE verifier missing")
	}
	stats := func() (good, bad uint32) {
		fs, err := gw.h.FilterList(gnv, netlink.MakeHandle(0xffff, 0))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			var actions []netlink.Action
			switch filter := f.(type) {
			case *netlink.Flower:
				actions = filter.Actions
			case *netlink.MatchAll:
				actions = filter.Actions
			default:
				continue
			}
			for _, a := range actions {
				if a.Attrs().Statistics != nil && a.Attrs().Statistics.Basic != nil {
					if f.Attrs().Priority == 10 {
						good += a.Attrs().Statistics.Basic.Packets
					} else if f.Attrs().Priority == 65535 {
						bad += a.Attrs().Statistics.Basic.Packets
					}
				}
			}
		}
		return
	}
	// WG ReceiveBytes and the nft INPUT observer precede GENEVE decapsulation
	// and tc ingress. Wait for the *same* authenticated packet to reach the
	// flower action before asserting its acceptance; an immediate FilterList
	// races the kernel receive path under load. Never count default-drop as a
	// successful authenticated probe.
	deadline = time.Now().Add(2 * time.Second)
	var accepted, rejected uint32
	for {
		accepted, rejected = stats()
		if accepted > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if accepted == 0 {
		t.Fatalf("Geneve verifier did not accept authenticated outer==inner PodIP/VNI; rejects=%d", rejected)
	}
	if err := netns.Set(clientNS); err != nil {
		t.Fatal(err)
	}
	payload[37] = 9 // inner source 10.42.2.9, outer remains 10.42.2.8.
	send(false)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := netns.Set(gwNS); err != nil {
			t.Fatal(err)
		}
		_, nowBad := stats()
		if nowBad > rejected {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, nowBad := stats()
	if nowBad <= rejected {
		t.Fatal("authenticated WG packet with forged GENEVE inner source bypassed verifier")
	}
}
