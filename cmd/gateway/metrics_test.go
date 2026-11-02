package main

import (
	"net"
	"testing"
)

func TestGatewayMetricsBindPrivateLoopback(t *testing.T) {
	host, port, err := net.SplitHostPort(gatewayMetricsAddr)
	if err != nil || host != "127.0.0.1" || port != "9902" {
		t.Fatalf("gateway metrics must remain loopback-only 9902: %q err=%v", gatewayMetricsAddr, err)
	}
}
