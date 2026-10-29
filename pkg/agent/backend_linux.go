//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
)

// BackendFactory runs only after InNamespace has entered the selected Pod netns.
type BackendFactory func() (datapath.Backend, error)

// resolveBackend fails closed for absent/unknown modes. The eBPF constructor
// is injected at integration time; it must never silently choose iproute.
func resolveBackend(mode string, ebpfFactory BackendFactory) (BackendFactory, error) {
	switch mode {
	case "", "iproute":
		return func() (datapath.Backend, error) { return iproute.New() }, nil
	case "ebpf":
		if ebpfFactory == nil {
			return nil, errors.New("eBPF backend unavailable")
		}
		return ebpfFactory, nil
	default:
		return nil, fmt.Errorf("unsupported DATAPATH %q", mode)
	}
}
func backendMode(mode string) string {
	if mode == "" {
		return "iproute"
	}
	return mode
}

// ClientVerifier is an optional backend capability for safe restart adoption.
// An eBPF marker alone is insufficient: tc attachment or policy maps may have
// been deleted while the agent was down. A backend without a verifier must be
// re-applied instead of claiming it is still programmed.
type ClientVerifier interface {
	VerifyClient(context.Context, datapath.ClientConfig) error
}

func canAdoptClient(ctx context.Context, backend datapath.Backend, cfg datapath.ClientConfig, mode string) bool {
	if backendMode(mode) != "ebpf" {
		return true // Keep M5 iproute restart behavior unchanged.
	}
	verifier, ok := backend.(ClientVerifier)
	return ok && verifier.VerifyClient(ctx, cfg) == nil
}

// checkWireGuardSupport runs after entering the workload netns and closes the
// backend before any registration or Pod-bound token request is attempted.
func checkWireGuardSupport(factory BackendFactory) error {
	backend, err := factory()
	if err != nil {
		return err
	}
	defer backend.Close()
	if _, ok := backend.(datapath.WireGuardManager); !ok {
		return errors.New("backend lacks WireGuardManager; refusing registration")
	}
	return nil
}
