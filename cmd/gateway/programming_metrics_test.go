package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/observability"
)

func TestGatewayProgrammingStartupRefreshFailureAndFailClosed(t *testing.T) {
	programming := observability.NewGatewayProgramming()
	var current atomic.Value
	current.Store(state{podUID: testPodUID})
	gaugeSnapshot := func() (bool, int) { s := current.Load().(state); return s.ready, s.effectiveMTU }
	handler := observability.GatewayHandler(gaugeSnapshot, programming)
	get := func() string {
		t.Helper()
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if result.Code != http.StatusOK {
			t.Fatalf("scrape status=%d", result.Code)
		}
		return result.Body.String()
	}
	assert := func(attempts, failures, samples string) {
		t.Helper()
		text := get()
		for _, line := range []string{attempts, failures, samples} {
			if !strings.Contains(text, "\n"+line+"\n") {
				t.Fatalf("metric %q absent: %s", line, text)
			}
		}
		if strings.Contains(text, "10.42.1.8") || strings.Contains(text, testPodUID) || strings.Contains(text, "private-config") || strings.Contains(text, "{client=") {
			t.Fatal("private identity in metrics")
		}
	}
	applied := 0
	var fail bool
	apply := observedGatewayApply(programming, func(_ context.Context, cfg datapath.GatewayConfig) error {
		applied++
		if fail {
			return errors.New("private-config 10.42.1.8")
		}
		return nil
	})
	cfg, hash := snapshot(t, configA)
	cfg.UpstreamHealthy = false
	if err := apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	} // initial startup before handler listen
	assert("ratatoskr_gateway_programming_attempts_total 1", "ratatoskr_gateway_programming_errors_total 0", "ratatoskr_gateway_programming_duration_seconds_count 1")
	g := &gatewayReconciler{current: &current, podUID: testPodUID, cfg: cfg, apply: apply}
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	assert("ratatoskr_gateway_programming_attempts_total 2", "ratatoskr_gateway_programming_errors_total 0", "ratatoskr_gateway_programming_duration_seconds_count 2")
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Fatalf("unchanged ready config reapplied %d times", applied)
	}
	fail = true
	newCfg, newHash := snapshot(t, configB)
	if err := g.refresh(context.Background(), readSnapshot(newCfg, newHash), noClamp, goodProbe); err == nil {
		t.Fatal("expected failed changed config")
	}
	assert("ratatoskr_gateway_programming_attempts_total 3", "ratatoskr_gateway_programming_errors_total 1", "ratatoskr_gateway_programming_duration_seconds_count 3")
	if err := g.failClosed(context.Background(), true); err == nil {
		t.Fatal("failed fail-closed apply reported success")
	}
	assert("ratatoskr_gateway_programming_attempts_total 4", "ratatoskr_gateway_programming_errors_total 2", "ratatoskr_gateway_programming_duration_seconds_count 4")
}
