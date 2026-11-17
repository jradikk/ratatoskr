package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestWaitAgentProgressHasOnlyFixedStagesAndNeverHardFiveSecondTimeout(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	calls := 0
	start := time.Now()
	err := waitForAgentProgress(context.Background(), func() (bool, error) { calls++; return calls >= 6, nil }, 10*time.Millisecond, log)
	if err != nil || calls != 6 || time.Since(start) > time.Second {
		t.Fatalf("marker delayed or skipped: calls=%d err=%v", calls, err)
	}
	for _, field := range []string{"waiting-marker", "ready", "elapsedMs"} {
		if !strings.Contains(output.String(), field) {
			t.Fatalf("missing fixed waiter log %q", field)
		}
	}
	output.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 1150*time.Millisecond)
	defer cancel()
	err = waitForAgentProgress(ctx, func() (bool, error) { return false, nil }, 10*time.Millisecond, log)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(output.String(), "wait-init pending") ||
		!strings.Contains(output.String(), "canceled") {
		t.Fatalf("marker wait timed out itself or progress missing: %v", err)
	}
	output.Reset()
	if err = waitForAgentProgress(context.Background(), func() (bool, error) { return false, errors.New("PRIVATE_KEY") }, time.Millisecond, log); err == nil || strings.Contains(output.String(), "PRIVATE_KEY") {
		t.Fatal("private marker read error leaked into wait-init logs")
	}
}
