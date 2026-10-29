package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestCompleteConfigAfterCNI(t *testing.T) {
	t.Setenv("POD_UID", "test-uid")
	t.Setenv("POD_NAME", "payments-0")
	t.Setenv("POD_NAMESPACE", "payments")
	c := &datapath.ClientConfig{GatewayID: 7, Endpoint: netip.MustParseAddr("10.42.2.4"), Exclusions: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}}
	if err := completeConfig(c, "10.42.1.8", 1500); err != nil {
		t.Fatal(err)
	}
	if c.PodIP.String() != "10.42.1.8" || c.MTU != 1450 || c.Identity.UID != "test-uid" || c.Identity.Pod != "payments-0" || c.Identity.Namespace != "payments" {
		t.Fatalf("incomplete post-CNI config: %#v", c)
	}
}
func TestIncompleteOrInvalidConfigFailsClosed(t *testing.T) {
	base := datapath.ClientConfig{GatewayID: 7, Endpoint: netip.MustParseAddr("10.42.2.4")}
	for _, tc := range []struct {
		name, addr string
		mtu        int
	}{{"missing pod ip", "", 1500}, {"invalid pod ip", "not-an-ip", 1500}, {"missing mtu", "10.42.1.8", 0}, {"too small", "10.42.1.8", 600}} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			if err := completeConfig(&c, tc.addr, tc.mtu); err == nil {
				t.Fatal("invalid injected config was accepted")
			} else if strings.Contains(err.Error(), "not-an-ip") {
				t.Fatal("config value should not be logged")
			}
		})
	}
}
func TestExplicitManualConfigPreserved(t *testing.T) {
	cfg := datapath.ClientConfig{PodIP: netip.MustParseAddr("10.42.1.8"), GatewayID: 7, MTU: 1400}
	if err := completeConfig(&cfg, "", 0); err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 1400 || cfg.PodIP.String() != "10.42.1.8" {
		t.Fatal("manual M1 config changed")
	}
}
