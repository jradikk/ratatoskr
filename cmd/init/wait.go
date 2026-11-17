package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	return waitForAgentProgress(ctx, lookup, interval, nil)
}

func waitForAgentProgress(ctx context.Context, lookup func() (bool, error), interval time.Duration, log *slog.Logger) error {
	if lookup == nil || interval <= 0 {
		return errors.New("agent readiness probe unavailable")
	}
	started := time.Now()
	lastProgress := started
	if log != nil {
		log.Info("wait-init startup", "stage", "waiting-marker")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ready, err := lookup()
		if err != nil {
			if log != nil {
				log.Warn("wait-init failed", "stage", "marker-read", "elapsedMs", time.Since(started).Milliseconds())
			}
			return fmt.Errorf("check agent datapath marker: %w", err)
		}
		if ready {
			if log != nil {
				log.Info("wait-init ready", "stage", "ready", "elapsedMs", time.Since(started).Milliseconds())
			}
			return nil
		}
		if log != nil && time.Since(lastProgress) >= time.Second {
			lastProgress = time.Now()
			log.Info("wait-init pending", "stage", "waiting-marker", "elapsedMs", time.Since(started).Milliseconds())
		}
		select {
		case <-ctx.Done():
			if log != nil {
				log.Warn("wait-init stopped", "stage", "canceled", "elapsedMs", time.Since(started).Milliseconds())
			}
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
	return waitForAgentProgress(ctx, markerReady, 250*time.Millisecond, slog.Default())
}
