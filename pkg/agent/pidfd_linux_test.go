//go:build linux

package agent

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPinnedPIDExitAndCandidateGuards(t *testing.T) {
	if err := checkPIDAlive(-1); err == nil {
		t.Fatal("invalid pidfd accepted")
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd unavailable: %v", err)
	}
	defer unix.Close(fd)
	if err := checkPIDAlive(fd); err != nil {
		t.Fatalf("live pidfd rejected: %v", err)
	}
	if err := verifyPIDNetns(fd, nil); err == nil {
		t.Fatal("nil candidate accepted")
	}
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if err := verifyPIDNetns(fd, self); err == nil {
		t.Fatalf("self candidate should fail before setns: %v", err)
	}
	// The verifier rejection must not move the OS thread's namespace.
	if err := rejectHost(self); err == nil && !errors.Is(err, unix.EACCES) {
		t.Fatal("self netns unexpectedly accepted")
	}
}

func TestHostPIDNamespaceSampleRestoresThread(t *testing.T) {
	pidfd, err := unix.PidfdOpen(1, 0)
	if err != nil {
		t.Skipf("host PID1 unavailable in test namespace: %v", err)
	}
	defer unix.Close(pidfd)
	// Nonprivileged CI cannot setns: refusal must not move this OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	_, err = pinnedNetnsStat(pidfd)
	if err == nil {
		t.Skip("test process has sufficient setns privilege; privileged test covers host rejection")
	}
	after, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	var prior, current unix.Stat_t
	if err := unix.Fstat(int(before.Fd()), &prior); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(after.Fd()), &current); err != nil {
		t.Fatal(err)
	}
	if !sameNetns(prior, current) {
		t.Fatal("failed host pidfd setns changed caller thread namespace")
	}
}

func TestMissingCRIPathAndDeadPID(t *testing.T) {
	info := map[string]string{"info": `{"pid":999999999,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/var/run/netns/sandbox"}]}}}`}
	if f, err := openSandboxNetns(info, "uid"); err == nil {
		f.Close()
		t.Fatal("accepted dead sandbox PID")
	}
	info = map[string]string{"info": `{"pid":1,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/var/run/netns/../escape"}]}}}`}
	if f, err := openSandboxNetns(info, "uid"); err == nil {
		f.Close()
		t.Fatal("accepted host PID or traversal")
	}
}
