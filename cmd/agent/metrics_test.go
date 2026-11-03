package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/observability"
)

func TestAgentMetricsServerPodIPAndShutdown(t *testing.T) {
	t.Setenv("METRICS_BIND_ADDRESS", "")
	if agentMetricsAddr != "0.0.0.0:9903" {
		t.Fatalf("agent Pod-IP metrics address changed: %q", agentMetricsAddr)
	}
	programming := observability.NewAgentProgramming()
	server, listener, err := agentMetricsServer(programming)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if addr, ok := listener.Addr().(*net.TCPAddr); !ok || !addr.IP.IsUnspecified() || addr.Port != 9903 {
		t.Fatalf("metrics listener is not fixed loopback tcp4: %s", listener.Addr())
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://127.0.0.1:9903/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "ratatoskr_agent_programming_attempts_total") {
		t.Fatalf("private metrics endpoint unavailable: status=%d err=%v", response.StatusCode, err)
	}
	response, err = client.Get("http://127.0.0.1:9903/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("health route exposed on private metrics listener")
	}
	if _, _, err := agentMetricsServer(programming); err == nil {
		t.Fatal("colliding node-local metrics listener did not fail startup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("metrics server error after shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("metrics server did not exit after bounded shutdown")
	}
}
