package controller

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestGatewayProbeTransportReusesConnections(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ready":true,"exitIP":"192.0.2.1"}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	client := newGatewayHTTPClient()
	defer client.CloseIdleConnections()
	for i := 0; i < 200; i++ {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		var info gatewayInfo
		if err = decodeGatewayInfo(response, &info); err != nil {
			t.Fatal(err)
		}
		if !info.Ready {
			t.Fatal("decoded readiness lost")
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("200 probes used %d connections", connections.Load())
	}
	transport := client.Transport.(*http.Transport)
	if transport.IdleConnTimeout <= 0 || transport.MaxConnsPerHost != 2 {
		t.Fatal("probe connections unbounded")
	}
	var first, second GatewayReconciler
	if first.gatewayHTTPClient() != second.gatewayHTTPClient() {
		t.Fatal("default transport recreated per reconcile")
	}
}

func TestGatewayProbeLocalAddressFailureIsActionable(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: syscall.EADDRNOTAVAIL}
	category, advice := gatewayProbeAdvice(err)
	if category != "LocalAddressUnavailable" || advice == "" {
		t.Fatal(category, advice)
	}
	category, _ = gatewayProbeAdvice(context.DeadlineExceeded)
	if category != "Timeout" {
		t.Fatal(category)
	}
	category, _ = gatewayProbeAdvice(errors.New("private upstream body"))
	if category != "ProbeFailed" {
		t.Fatal(category)
	}
}
