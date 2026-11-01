package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func linkStats(name string, rxBytes, txBytes, rxPackets, txPackets uint64) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name,
		Statistics: &netlink.LinkStatistics{RxBytes: rxBytes, TxBytes: txBytes, RxPackets: rxPackets, TxPackets: txPackets}}}
}
func linkMetrics(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics response=%d", response.Code)
	}
	return response.Body.String()
}
func checkLinkMetric(t *testing.T, text, metric, role, value string) {
	t.Helper()
	line := "\nratatoskr_gateway_link_" + metric + `{role="` + role + `"} ` + value + "\n"
	if strings.Count(text, line) != 1 {
		t.Fatalf("metric %q missing or duplicated", line)
	}
}

func TestGatewayLinkFreshResetUnknownAndStrictRoles(t *testing.T) {
	links := map[string]netlink.Link{
		"gnv0":      linkStats("gnv0", 11, 12, 13, 14),
		"upstream0": linkStats("upstream0", 21, 22, 23, 24),
		"rtkwg0":    linkStats("rtkwg0", 31, 32, 33, 34),
	}
	fail := ""
	reader := func(name string) (netlink.Link, error) {
		if name == fail {
			return nil, errors.New("private PodUID 10.42.1.8")
		}
		return links[name], nil
	}
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "wireguard"}[encrypted], func(t *testing.T) {
			traffic := NewGatewayLinkTraffic(encrypted, reader)
			handler := GatewayHandler(func() (bool, int) { return true, 1320 }, NewGatewayProgramming(), traffic)
			first := linkMetrics(t, handler)
			for _, role := range []string{"geneve", "upstream"} {
				checkLinkMetric(t, first, "sample_ok", role, "1")
			}
			checkLinkMetric(t, first, "receive_bytes", "geneve", "11")
			checkLinkMetric(t, first, "transmit_bytes", "geneve", "12")
			checkLinkMetric(t, first, "receive_packets", "upstream", "23")
			checkLinkMetric(t, first, "transmit_packets", "upstream", "24")
			if encrypted {
				checkLinkMetric(t, first, "sample_ok", "wireguard", "1")
				checkLinkMetric(t, first, "receive_bytes", "wireguard", "31")
			} else if strings.Contains(first, `role="wireguard"`) {
				t.Fatal("plaintext mode exported missing WG link")
			}
			if strings.Contains(first, "10.42.1.8") || strings.Contains(first, "pod_uid") || strings.Contains(first, "rtkwg0") || strings.Contains(first, "{name=") {
				t.Fatal("metric leaked identity, device name, or unbounded label")
			}
			// Link recreation resets counters: never preserve stale high samples.
			links["gnv0"] = linkStats("gnv0", 0, 1, 0, 1)
			reset := linkMetrics(t, handler)
			checkLinkMetric(t, reset, "receive_bytes", "geneve", "0")
			checkLinkMetric(t, reset, "transmit_packets", "geneve", "1")
			// Unknown sampling reports 0 sample_ok, NOT a fabricated zero byte count.
			fail = "gnv0"
			unknown := linkMetrics(t, handler)
			checkLinkMetric(t, unknown, "sample_ok", "geneve", "0")
			if strings.Contains(unknown, `ratatoskr_gateway_link_receive_bytes{role="geneve"}`) {
				t.Fatal("unknown Geneve sample exported stale or zero bytes")
			}
			checkLinkMetric(t, unknown, "sample_ok", "upstream", "1")
			fail = ""
			links["gnv0"] = linkStats("gnv0", 11, 12, 13, 14)
		})
	}
}

func TestGatewayLinkReadTimeoutBoundedSingleWorker(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	traffic := NewGatewayLinkTraffic(true, func(name string) (netlink.Link, error) {
		calls.Add(1)
		if name == "gnv0" {
			close(started)
			<-release
		}
		return linkStats(name, 1, 2, 3, 4), nil
	})
	handler := GatewayHandler(func() (bool, int) { return true, 1400 }, NewGatewayProgramming(), traffic)
	first := make(chan string, 1)
	go func() { first <- linkMetrics(t, handler) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("kernel link read never started")
	}
	select {
	case text := <-first:
		for _, role := range []string{"geneve", "upstream", "wireguard"} {
			checkLinkMetric(t, text, "sample_ok", role, "0")
		}
		if strings.Contains(text, "ratatoskr_gateway_link_receive_bytes") {
			t.Fatal("timeout exported stale bytes")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("scrape did not time out")
	}
	second := linkMetrics(t, handler)
	if calls.Load() != 1 {
		t.Fatal("a blocked kernel reader spawned a second worker")
	}
	for _, role := range []string{"geneve", "upstream", "wireguard"} {
		checkLinkMetric(t, second, "sample_ok", role, "0")
	}
	close(release)
}
