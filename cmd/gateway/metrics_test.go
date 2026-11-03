package main

import (
	"net"
	"testing"
)

func TestGatewayMetricsBindPodIPDefault(t *testing.T) {
	host, port, err := net.SplitHostPort(gatewayMetricsAddr)
	if err != nil || host != "0.0.0.0" || port != "9902" {
		t.Fatalf("gateway metrics must bind Pod IP on 9902 by default: %q err=%v", gatewayMetricsAddr, err)
	}
}
