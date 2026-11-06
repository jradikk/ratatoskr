//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRecheckPinnedNamespaceInterruptedStatIsNotLostProof(t *testing.T) {
	// A complete proof with a deliberately invalid UID must reach the PID
	// cgroup check, not fail at the injected transient FD stat interruption.
	service := &changingCRI{id: "sandbox", ns: "ns", name: "pod", uid: "not-my-cgroup", ip: "10.2.0.3", pid: os.Getpid(), path: "/var/run/netns/sandbox"}
	fd, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	proof := service.proof(fd)
	proof.pidfd, err = unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd unavailable: %v", err)
	}
	defer unix.Close(proof.pidfd)
	calls := 0
	err = recheckSandboxWithStat(context.Background(), service, proof, fd, func(fd int, stat *unix.Stat_t) error {
		calls++
		if calls == 1 {
			return unix.EINTR
		}
		return unix.Fstat(fd, stat)
	})
	if calls != 2 || err == nil || !strings.Contains(err.Error(), "cgroup") || strings.Contains(err.Error(), "interrupted system call") {
		t.Fatalf("interrupted stat skipped later proof verification: calls=%d err=%v", calls, err)
	}
}

func TestPinnedNamespaceStatRetriesInterruptedAndRejectsStaleData(t *testing.T) {
	var inode unix.Stat_t
	calls := 0
	err := statPinnedNamespaceWith(42, &inode, func(fd int, out *unix.Stat_t) error {
		calls++
		if fd != 42 {
			t.Fatal("pinned FD changed during stat retry")
		}
		if calls == 1 {
			out.Ino = 999
			return unix.EINTR
		}
		if out.Ino != 0 {
			t.Fatal("interrupted stat result was reused")
		}
		out.Ino = 123
		return nil
	})
	if err != nil || calls != 2 || inode.Ino != 123 {
		t.Fatalf("stat retry calls=%d inode=%d err=%v", calls, inode.Ino, err)
	}
	calls = 0
	err = statPinnedNamespaceWith(42, &inode, func(int, *unix.Stat_t) error {
		calls++
		return unix.EINTR
	})
	if !errors.Is(err, unix.EINTR) || calls != 16 || inode.Ino != 0 {
		t.Fatalf("stat retry accepted persistent EINTR calls=%d inode=%d err=%v", calls, inode.Ino, err)
	}
}

func TestInterruptedNamespaceSwitchChecksThreadBeforeRetry(t *testing.T) {
	source := unix.Stat_t{Dev: 7, Ino: 11}
	destination := unix.Stat_t{Dev: 7, Ino: 12}
	for _, transitionOnInterrupt := range []bool{false, true} {
		current := source
		calls := 0
		err := switchThreadNamespaceWith(source, destination, 44, func(fd, kind int) error {
			calls++
			if fd != 44 || kind != unix.CLONE_NEWNET {
				t.Fatal("switched unexpected FD or namespace type")
			}
			if transitionOnInterrupt || calls == 2 {
				current = destination
			}
			if calls == 1 {
				return unix.EINTR
			}
			return nil
		}, func() (unix.Stat_t, error) { return current, nil })
		want := 2
		if transitionOnInterrupt {
			want = 1
		}
		if err != nil || calls != want {
			t.Fatalf("transitionOnInterrupt=%v calls=%d err=%v", transitionOnInterrupt, calls, err)
		}
	}
	calls := 0
	if err := switchThreadNamespaceWith(source, destination, 44, func(int, int) error { calls++; return unix.EINTR }, func() (unix.Stat_t, error) { return source, nil }); !errors.Is(err, unix.EINTR) || calls != 16 {
		t.Fatalf("persistent interruption was not bounded: calls=%d err=%v", calls, err)
	}
	if err := switchThreadNamespaceWith(source, destination, 44, func(int, int) error { return unix.EINTR }, func() (unix.Stat_t, error) { return unix.Stat_t{Dev: 7, Ino: 13}, nil }); err == nil {
		t.Fatal("unexpected thread namespace was accepted")
	}
}

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
