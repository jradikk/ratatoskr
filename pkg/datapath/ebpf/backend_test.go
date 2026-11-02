//go:build linux

package ebpf

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestEncryptedModeRefusesBeforeKernelChanges(t *testing.T) {
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c := datapath.ClientConfig{PodIP: netip.MustParseAddr("192.0.2.8"), GatewayID: 7, MTU: 1320, Endpoint: netip.MustParseAddr("192.0.2.9"), Encryption: "wireguard", GatewayPublicKey: "public", RegistrationCACert: "public CA"}
	if err := b.ApplyClient(context.Background(), c); err == nil || !strings.Contains(err.Error(), "WireGuard") {
		t.Fatalf("WireGuard must never silently downgrade: %v", err)
	}
	g := datapath.GatewayConfig{PodIP: c.PodIP, GatewayID: 7, MTU: 1320, Encryption: "wireguard"}
	if err := b.ApplyGateway(context.Background(), g); err == nil || !strings.Contains(err.Error(), "WireGuard") {
		t.Fatalf("WireGuard gateway must never downgrade: %v", err)
	}
}
func TestCIDRMaskAndIdentity(t *testing.T) {
	want := prefixKey(netip.MustParsePrefix("10.4.5.6/16"))
	if want.Prefixlen != 16 || want.Addr != addrU32(netip.MustParseAddr("10.4.0.0")) {
		t.Fatalf("unmasked BPF exclusion key: %+v", want)
	}
	if rk := ruleKey(3, netip.MustParsePrefix("10.4.5.6/16")); rk.Prefixlen != 48 || rk.Rule != 3 {
		t.Fatalf("bad rule LPM key %+v", rk)
	}
	a := identityTLV(datapath.ClientConfig{Identity: datapath.Identity{Namespace: "ns", UID: "u1"}})
	b := identityTLV(datapath.ClientConfig{Identity: datapath.Identity{Namespace: "ns", UID: "u2"}})
	if a.Identity == b.Identity || a.Len != 2 || a.Type != 1 {
		t.Fatal("identity TLV failed to distinguish client UIDs")
	}
}
