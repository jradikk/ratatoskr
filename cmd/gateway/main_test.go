package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayInnerMTUUsesObservedPodCarrier(t *testing.T) {
	for _, tc := range []struct {
		name              string
		config, pod, want int
		fail              bool
	}{{"flannel", 1400, 1450, 1400, false}, {"smaller CNI MTU", 1400, 1360, 1310, false}, {"IPv4 small but valid", 1400, 650, 600, false}, {"below IPv4 minimum", 1400, 600, 0, true}, {"invalid configured MTU", 0, 1500, 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gatewayInnerMTU(tc.config, tc.pod)
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("gateway MTU=%d error=%v; want=%d fail=%t", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestEncryptedGatewayMTUBudget(t *testing.T) {
	for _, tc := range []struct {
		name              string
		config, pod, want int
		fail              bool
	}{{"flannel encrypted", 1400, 1450, 1340, false}, {"smaller carrier", 1400, 1360, 1250, false}, {"too small", 1400, 680, 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gatewayInnerMTUForMode(tc.config, tc.pod, "wireguard")
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("got=%d err=%v want=%d", got, err, tc.want)
			}
		})
	}
}

func TestReadGatewayConfigReload(t *testing.T) {
	t.Setenv("POD_IP", "10.42.2.4")
	path := filepath.Join(t.TempDir(), "gateway.json")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"gatewayID":7,"mtu":1400,"clients":["10.42.1.8"]}`)
	cfg, err := readGatewayConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PodIP.String() != "10.42.2.4" || len(cfg.Clients) != 1 || cfg.Clients[0].String() != "10.42.1.8" {
		t.Fatal("initial ConfigMap invalid")
	}
	write(`{"gatewayID":7,"mtu":1400,"clients":["10.42.1.8","10.42.1.9"]}`)
	next, err := readGatewayConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Clients) != 2 || len(cfg.Clients) != 1 {
		t.Fatal("new selected pod was not observed from projected config")
	}
}

func TestReadGatewayConfigRejectsUnsafeReplacement(t *testing.T) {
	t.Setenv("POD_IP", "10.42.2.4")
	path := filepath.Join(t.TempDir(), "gateway.json")
	for _, v := range []string{`{"gatewayID":7,"mtu":1400,"clients":["2001:db8::1"]}`, `{"gatewayID":7,"mtu":1400,"clients":[],"rogue":"sentinel"}`, `{"gatewayID":7,"mtu":1400,"clients":{}}`, `{"gatewayID":7,"mtu":1400,"clients":[]} {"gatewayID":7}`, strings.Repeat("x", 1<<20+1)} {
		if err := os.WriteFile(path, []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readGatewayConfig(path); err == nil {
			t.Fatal("invalid config accepted")
		} else if strings.Contains(err.Error(), "sentinel") {
			t.Fatal("config value appeared in error")
		}
	}
}
