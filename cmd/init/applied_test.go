package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func ackTestConfig() datapath.ClientConfig {
	return datapath.ClientConfig{PodIP: netip.MustParseAddr("10.1.0.2"), GatewayID: 11, Endpoint: netip.MustParseAddr("10.2.0.3"), Identity: datapath.Identity{UID: "workload-uid"}}
}
func ackTestBytes(t *testing.T, c datapath.ClientConfig) []byte {
	t.Helper()
	b, err := json.Marshal(gatewayAppliedAck{WorkloadUID: c.Identity.UID, WorkloadPodIP: c.PodIP.String(), GatewayUID: "gateway-uid", GatewayID: c.GatewayID, GatewayPodUID: "endpoint-uid", GatewayPodIP: c.Endpoint.String(), ConfigHash: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestAppliedAckRejectsForgeryAndMalformedData(t *testing.T) {
	cfg := ackTestConfig()
	raw := ackTestBytes(t, cfg)
	if err := validateAppliedAck(raw, cfg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		modify func(*datapath.ClientConfig)
	}{
		{"empty", []byte(""), nil}, {"malformed", []byte("{"), nil}, {"trailing", append(append([]byte{}, raw...), []byte(" true")...), nil},
		{"forged workload UID", raw, func(c *datapath.ClientConfig) { c.Identity.UID = "other" }},
		{"forged workload IP", raw, func(c *datapath.ClientConfig) { c.PodIP = netip.MustParseAddr("10.1.0.9") }},
		{"wrong gateway ID", raw, func(c *datapath.ClientConfig) { c.GatewayID = 12 }},
		{"wrong endpoint", raw, func(c *datapath.ClientConfig) { c.Endpoint = netip.MustParseAddr("10.2.0.4") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.modify != nil {
				tc.modify(&c)
			}
			if err := validateAppliedAck(tc.raw, c); err == nil {
				t.Fatal("forged or malformed ack accepted")
			}
		})
	}
}
func TestAppliedAckWaitsForProjectionWithoutFixedSleep(t *testing.T) {
	cfg := ackTestConfig()
	raw := ackTestBytes(t, cfg)
	calls := 0
	read := func() ([]byte, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("projected volume not updated")
		}
		return raw, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitAppliedAck(ctx, cfg, read, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if calls < 3 {
		t.Fatal("ack lag was bypassed")
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := waitAppliedAck(cancelled, cfg, func() ([]byte, error) { return []byte("pending"), nil }, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait did not stop on cancel: %v", err)
	}
}
