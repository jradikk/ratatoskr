package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGatewayHealthAndMeasuredMTUMetricsWithoutLabels(t *testing.T) {
	var current atomic.Value
	current.Store(struct {
		ready bool
		mtu   int
	}{})
	handler := GatewayHandler(func() (bool, int) {
		s := current.Load().(struct {
			ready bool
			mtu   int
		})
		return s.ready, s.mtu
	}, NewGatewayProgramming(), NewGatewayLinkTraffic(false, nil))
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
		for _, name := range []string{"ratatoskr_gateway_upstream_healthy", "ratatoskr_gateway_effective_mtu_bytes"} {
			if strings.Count(text, "\n"+name+" ") != 1 {
				t.Fatalf("missing or duplicated metric %s: %s", name, text)
			}
		}
		return text
	}
	assert := func(ready bool, mtu int, healthValue, mtuValue string) {
		t.Helper()
		current.Store(struct {
			ready bool
			mtu   int
		}{ready, mtu})
		got := scrape()
		for _, line := range []string{healthValue, mtuValue} {
			if !strings.Contains(got, line+"\n") {
				t.Fatalf("gateway metric %q missing: %s", line, got)
			}
		}
	}
	assert(false, 0, "ratatoskr_gateway_upstream_healthy 0", "ratatoskr_gateway_effective_mtu_bytes 0")
	assert(true, 1380, "ratatoskr_gateway_upstream_healthy 1", "ratatoskr_gateway_effective_mtu_bytes 1380")
	assert(false, 1380, "ratatoskr_gateway_upstream_healthy 0", "ratatoskr_gateway_effective_mtu_bytes 0")
	assert(true, 0, "ratatoskr_gateway_upstream_healthy 1", "ratatoskr_gateway_effective_mtu_bytes 0")
}
