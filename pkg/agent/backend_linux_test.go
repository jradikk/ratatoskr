//go:build linux

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

type stubBackend struct{ closed *bool }

func (*stubBackend) ApplyClient(context.Context, datapath.ClientConfig) error   { return nil }
func (*stubBackend) RemoveClient(context.Context, datapath.ClientConfig) error  { return nil }
func (*stubBackend) ApplyGateway(context.Context, datapath.GatewayConfig) error { return nil }
func (s *stubBackend) Close()                                                   { *s.closed = true }

func TestBackendModeFailsClosed(t *testing.T) {
	for _, mode := range []string{"invalid", "eBPF", "ebpf ", "none"} {
		if f, err := resolveBackend(mode, nil); err == nil || f != nil {
			t.Errorf("accepted unsupported datapath %q", mode)
		}
	}
	if f, err := resolveBackend("ebpf", nil); err == nil || f != nil {
		t.Fatal("accepted ebpf without constructor")
	}
	for _, mode := range []string{"", "iproute"} {
		if f, err := resolveBackend(mode, nil); err != nil || f == nil {
			t.Fatalf("iproute factory %q: %v", mode, err)
		}
	}
}
func TestEBPFFactoryNeverFallsBackToIproute(t *testing.T) {
	sentinel := errors.New("ebpf unavailable")
	calls := 0
	selected, err := resolveBackend("ebpf", func() (datapath.Backend, error) { calls++; return nil, sentinel })
	if err != nil {
		t.Fatal(err)
	}
	_, err = selected()
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("ebpf selection fell back: calls %d, err %v", calls, err)
	}
}
func TestEBPFWireGuardUnsupportedBeforeRegistration(t *testing.T) {
	closed := false
	factory, err := resolveBackend("ebpf", func() (datapath.Backend, error) { return &stubBackend{closed: &closed}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := checkWireGuardSupport(factory); err == nil || !strings.Contains(err.Error(), "WireGuardManager") || !closed {
		t.Fatalf("unmanaged WG accepted or leaked backend: closed=%t, err=%v", closed, err)
	}
}
func TestModeHashBindsBackendWithoutBreakingIprouteAdoption(t *testing.T) {
	c := datapath.ClientConfig{GatewayID: 9}
	if HashForMode(c, "") != Hash(c) || HashForMode(c, "iproute") != Hash(c) {
		t.Fatal("iproute M5 hash changed")
	}
	if HashForMode(c, "ebpf") == Hash(c) {
		t.Fatal("ebpf adopted iproute marker")
	}
}
