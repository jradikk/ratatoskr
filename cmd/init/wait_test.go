package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitAgentRequiresMarkerAndHandlesShutdown(t *testing.T) {
	calls := 0
	if err := waitForAgent(context.Background(), func() (bool, error) { calls++; return calls >= 3, nil }, time.Millisecond); err != nil || calls != 3 {
		t.Fatalf("marker wait: calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForAgent(ctx, func() (bool, error) { return false, nil }, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("startup gate ignored cancellation: %v", err)
	}
	if err := waitForAgent(context.Background(), func() (bool, error) { return false, errors.New("netlink denied") }, time.Millisecond); err == nil {
		t.Fatal("netns marker read failure was silently ignored")
	}
}
