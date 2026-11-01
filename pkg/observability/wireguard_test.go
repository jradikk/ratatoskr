package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardScrapesDoNotStackTimedOutKernelReads(t *testing.T) {
	start := make(chan struct{})
	finish := make(chan struct{})
	var calls atomic.Int32
	handler := WireGuardHandler(func() (bool, int) { return true, 1400 }, NewGatewayProgramming(), "rtkwg0", func(string) (*wgtypes.Device, error) {
		calls.Add(1)
		close(start)
		<-finish
		return &wgtypes.Device{}, nil
	})
	first := make(chan string, 1)
	go func() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		first <- w.Body.String()
	}()
	select {
	case <-start:
	case <-time.After(time.Second):
		t.Fatal("first kernel read never started")
	}
	select {
	case text := <-first:
		if !strings.Contains(text, "ratatoskr_gateway_wireguard_sample_ok 0\n") {
			t.Fatalf("timeout incorrectly reported as known: %s", text)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("bounded sample never timed out")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if calls.Load() != 1 || !strings.Contains(w.Body.String(), "ratatoskr_gateway_wireguard_sample_ok 0\n") {
		t.Fatal("concurrent timeout spawned a second kernel read")
	}
	close(finish)
}

func TestWireGuardMetricsKnownZeroMeasuredAndUnknown(t *testing.T) {
	device := &wgtypes.Device{}
	fail := false
	handler := WireGuardHandler(func() (bool, int) { return true, 1400 }, NewGatewayProgramming(), "rtkwg0", func(string) (*wgtypes.Device, error) {
		if fail {
			return nil, errors.New("kernel unavailable")
		}
		return device, nil
	})
	scrape := func() string {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if w.Code != 200 {
			t.Fatalf("scrape code %d", w.Code)
		}
		text := w.Body.String()
		if strings.Contains(text, "uid=") || strings.Contains(text, "peer=") || strings.Contains(text, "publicKey") || strings.Contains(text, "go_gc_duration") {
			t.Fatalf("sensitive or runtime metrics present: %s", text)
		}
		return text
	}
	zero := scrape()
	for _, metric := range []string{"ratatoskr_gateway_wireguard_sample_ok 1", "ratatoskr_gateway_wireguard_installed_peers 0", "ratatoskr_gateway_wireguard_handshaken_peers 0", "ratatoskr_gateway_wireguard_latest_handshake_age_seconds -1", "ratatoskr_gateway_wireguard_receive_bytes 0", "ratatoskr_gateway_wireguard_transmit_bytes 0", "ratatoskr_gateway_upstream_healthy 1"} {
		if !strings.Contains(zero, metric+"\n") {
			t.Fatalf("known zero missing %q: %s", metric, zero)
		}
	}
	device.Peers = []wgtypes.Peer{{ReceiveBytes: 12, TransmitBytes: 24, LastHandshakeTime: time.Now().Add(-2 * time.Second)}}
	valid := scrape()
	for _, metric := range []string{"ratatoskr_gateway_wireguard_installed_peers 1", "ratatoskr_gateway_wireguard_handshaken_peers 1", "ratatoskr_gateway_wireguard_receive_bytes 12", "ratatoskr_gateway_wireguard_transmit_bytes 24"} {
		if !strings.Contains(valid, metric+"\n") {
			t.Fatalf("kernel sample missing %q: %s", metric, valid)
		}
	}
	fail = true
	unknown := scrape()
	if !strings.Contains(unknown, "ratatoskr_gateway_wireguard_sample_ok 0\n") || strings.Contains(unknown, "ratatoskr_gateway_wireguard_installed_peers ") {
		t.Fatalf("unknown mistaken for known zero: %s", unknown)
	}
}
