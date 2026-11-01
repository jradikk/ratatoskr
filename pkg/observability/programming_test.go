package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func metricText(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics response status=%d", response.Code)
	}
	return response.Body.String()
}
func metricLine(t *testing.T, text, line string) {
	t.Helper()
	if !strings.Contains(text, "\n"+line+"\n") {
		t.Fatalf("missing metric line %q: %s", line, text)
	}
}

func TestGatewayProgrammingCompletedAttemptsAndNoLabels(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{true: "wireguard", false: "plain"}[encrypted], func(t *testing.T) {
			programming := NewGatewayProgramming()
			snapshot := func() (bool, int) { return true, 1320 }
			handler := GatewayHandler(snapshot, programming, NewGatewayLinkTraffic(encrypted, nil))
			if encrypted {
				handler = WireGuardHandler(snapshot, programming, NewGatewayLinkTraffic(true, nil), NewGatewayPlaintextGuard(nil), "rtkwg0", func(string) (*wgtypes.Device, error) { return &wgtypes.Device{}, nil })
			}
			initial := metricText(t, handler)
			metricLine(t, initial, "ratatoskr_gateway_programming_attempts_total 0")
			metricLine(t, initial, "ratatoskr_gateway_programming_errors_total 0")
			metricLine(t, initial, "ratatoskr_gateway_programming_duration_seconds_count 0")
			sentinel := errors.New("private-token-10.42.1.8")
			if err := programming.Observe(func() error { time.Sleep(time.Millisecond); return sentinel }); !errors.Is(err, sentinel) {
				t.Fatal("observed error changed")
			}
			if err := programming.Observe(func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			got := metricText(t, handler)
			for _, expected := range []string{"ratatoskr_gateway_programming_attempts_total 2", "ratatoskr_gateway_programming_errors_total 1", "ratatoskr_gateway_programming_duration_seconds_count 2", "ratatoskr_gateway_programming_duration_seconds_bucket{le=\"+Inf\"} 2"} {
				metricLine(t, got, expected)
			}
			if strings.Contains(got, "private-token") || strings.Contains(got, "10.42.1.8") || strings.Contains(got, "uid=") || strings.Contains(got, "go_gc_duration") || strings.Contains(got, "{gateway=") {
				t.Fatal("metric export leaked untrusted data or labels")
			}
		})
	}
}

func TestGatewayProgrammingConcurrentAndPanicNotCompleted(t *testing.T) {
	programming := NewGatewayProgramming()
	const workers = 32
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			_ = programming.Observe(func() error {
				if i%2 != 0 {
					return errors.New("private")
				}
				return nil
			})
		}(i)
	}
	group.Wait()
	func() {
		defer func() {
			if recovered := recover(); recovered != "test-panic" {
				t.Fatalf("panic swallowed: %v", recovered)
			}
		}()
		_ = programming.Observe(func() error { panic("test-panic") })
	}()
	got := metricText(t, GatewayHandler(func() (bool, int) { return false, 0 }, programming, NewGatewayLinkTraffic(false, nil)))
	metricLine(t, got, "ratatoskr_gateway_programming_attempts_total 32")
	metricLine(t, got, "ratatoskr_gateway_programming_errors_total 16")
	metricLine(t, got, "ratatoskr_gateway_programming_duration_seconds_count 32")
}
