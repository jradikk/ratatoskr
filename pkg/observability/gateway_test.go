package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGatewayHealthMetricTracksReadinessWithoutLabels(t *testing.T) {
	var ready atomic.Bool
	handler := GatewayHandler(ready.Load)
	scrape := func() string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("scrape status %d: %s", resp.Code, resp.Body.String())
		}
		body, _ := io.ReadAll(resp.Body)
		text := string(body)
		if strings.Contains(text, "uid=") || strings.Contains(text, "secret=") || strings.Contains(text, "peer=") || strings.Contains(text, "go_gc_duration") {
			t.Fatalf("metric labels/runtime leakage: %s", text)
		}
		if strings.Count(text, "ratatoskr_gateway_upstream_healthy ") != 1 {
			t.Fatalf("missing or duplicated metric: %s", text)
		}
		return text
	}
	if got := scrape(); !strings.Contains(got, "ratatoskr_gateway_upstream_healthy 0\n") {
		t.Fatalf("startup not reported unhealthy: %s", got)
	}
	ready.Store(true)
	if got := scrape(); !strings.Contains(got, "ratatoskr_gateway_upstream_healthy 1\n") {
		t.Fatalf("healthy not reflected immediately: %s", got)
	}
	ready.Store(false)
	if got := scrape(); !strings.Contains(got, "ratatoskr_gateway_upstream_healthy 0\n") {
		t.Fatalf("failed backend did not reset gauge: %s", got)
	}
}
