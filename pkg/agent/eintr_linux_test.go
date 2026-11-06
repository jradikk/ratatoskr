//go:build linux

package agent

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInterruptedPollDoesNotMeanSandboxExited(t *testing.T) {
	calls := 0
	err := checkPIDAliveWithPoll(42, func(fds []unix.PollFd, timeout int) (int, error) {
		calls++
		if fds[0].Fd != 42 || timeout != 0 {
			t.Fatal("liveness poll changed")
		}
		if calls == 1 {
			return -1, unix.EINTR
		}
		return 0, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("live sandbox rejected after interruption: calls=%d err=%v", calls, err)
	}
}

func TestInterruptedPollStillDetectsExitedSandbox(t *testing.T) {
	calls := 0
	err := checkPIDAliveWithPoll(42, func(fds []unix.PollFd, _ int) (int, error) {
		calls++
		if calls == 1 {
			return -1, unix.EINTR
		}
		fds[0].Revents = unix.POLLIN
		return 1, nil
	})
	if err == nil || !strings.Contains(err.Error(), "sandbox process exited") {
		t.Fatalf("exit ignored: %v", err)
	}
}

func TestInterruptedOperationRetriesAreBounded(t *testing.T) {
	calls := 0
	_, err := retryInterrupted(func() (int, error) { calls++; return -1, unix.EINTR })
	if !errors.Is(err, unix.EINTR) || calls != 16 {
		t.Fatalf("unbounded retry: %d %v", calls, err)
	}
	calls = 0
	_, err = retryInterrupted(func() (int, error) { calls++; return -1, unix.EACCES })
	if !errors.Is(err, unix.EACCES) || calls != 1 {
		t.Fatalf("permission failure retried: %d %v", calls, err)
	}
}
