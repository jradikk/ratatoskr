package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/skaldhall/ratatoskr/pkg/platform"
)

const agentReadyLink = "rtk-ready"

// waitForAgent starts no application process and acquires no Kubernetes token.
// The marker exists only in this Pod netns; the agent creates it after a
// fail-closed datapath is installed. A marker in the host netns is irrelevant.
func waitForAgent(ctx context.Context, lookup func() (bool, error), interval time.Duration) error {
	if lookup == nil || interval <= 0 {
		return errors.New("agent readiness probe unavailable")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ready, err := lookup()
		if err != nil {
			return fmt.Errorf("check agent datapath marker: %w", err)
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for node agent datapath: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
func markerReady() (bool, error) {
	link, err := netlink.LinkByName(agentReadyLink)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) {
			return false, nil
		}
		return false, err
	}
	if link.Type() != "dummy" || link.Attrs().Flags&net.FlagUp == 0 {
		return false, nil
	}
	return true, nil
}
func runWaitAgent(ctx context.Context) error {
	if err := platform.CheckKernel(); err != nil {
		return err
	}
	return waitForAgent(ctx, markerReady, 250*time.Millisecond)
}
