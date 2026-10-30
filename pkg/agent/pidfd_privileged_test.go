//go:build linux && privileged

package agent

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestPIDFDNetnsHelper(t *testing.T) {
	if os.Getenv("RATATOSKR_PIDFD_HELPER") == "1" {
		time.Sleep(30 * time.Second)
	}
}

// A kubelet/API-verified agent anchors its own host network namespace.
// A candidate equal to that pinned namespace must be rejected before entry.
func TestPrivilegedHostNamespaceRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_SYS_ADMIN")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	sandbox, err := netns.New()
	if errors.Is(err, unix.EPERM) {
		t.Skip("CAP_SYS_ADMIN unavailable for isolated netns")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer sandbox.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			panic("failed to restore privileged host-check test namespace: " + err.Error())
		}
	}()
	hostFD, err := unix.Dup(int(original))
	if err != nil {
		t.Fatal(err)
	}
	hostCandidate := os.NewFile(uintptr(hostFD), "original host namespace")
	defer hostCandidate.Close()
	var anchored unix.Stat_t
	if err := unix.Fstat(int(hostCandidate.Fd()), &anchored); err != nil {
		t.Fatal(err)
	}
	previous := verifiedHost.Swap(&hostAnchor{fd: hostCandidate, stat: anchored})
	defer verifiedHost.Store(previous)
	if err := rejectHost(hostCandidate); err == nil {
		t.Fatal("pinned host network namespace accepted from a different self netns")
	}
	current, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	var want, have unix.Stat_t
	if err := unix.Fstat(int(sandbox), &want); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(current), &have); err != nil {
		t.Fatal(err)
	}
	if !sameNetns(want, have) {
		t.Fatal("host PID1 comparison failed to restore sandbox thread namespace")
	}
}

func TestPrivilegedPinnedPIDNetnsVerification(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_SYS_ADMIN")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	sandbox, err := netns.New()
	if errors.Is(err, unix.EPERM) {
		t.Skip("CAP_SYS_ADMIN unavailable for isolated netns")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer sandbox.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			panic("failed to restore privileged test network namespace: " + err.Error())
		}
	}()
	// Fork on this locked thread: the helper keeps the sandbox namespace alive
	// while the parent verifies against its pinned pidfd from the original netns.
	child := exec.Command(os.Args[0], "-test.run=^TestPIDFDNetnsHelper$")
	child.Env = append(os.Environ(), "RATATOSKR_PIDFD_HELPER=1")
	if err := child.Start(); err != nil {
		_ = netns.Set(original)
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	candidate, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		_ = netns.Set(original)
		t.Fatal(err)
	}
	defer candidate.Close()
	if err := netns.Set(original); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	originalFD, err := unix.Dup(int(original))
	if err != nil {
		t.Fatal(err)
	}
	anchorFD := os.NewFile(uintptr(originalFD), "privileged test host anchor")
	defer anchorFD.Close()
	var anchorStat unix.Stat_t
	if err := unix.Fstat(int(anchorFD.Fd()), &anchorStat); err != nil {
		t.Fatal(err)
	}
	previous := verifiedHost.Swap(&hostAnchor{fd: anchorFD, stat: anchorStat})
	defer verifiedHost.Store(previous)
	if err := verifyPIDNetns(fd, candidate); err != nil {
		t.Fatalf("pinned sandbox verification failed: %v", err)
	}
	current, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	if current.Close() != nil {
		t.Fatal("close thread namespace")
	}
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if err := verifyPIDNetns(fd, self); err == nil {
		t.Fatal("host namespace candidate accepted")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("expected killed helper")
	}
	if err := checkPIDAlive(fd); err == nil {
		t.Fatal("dead pidfd accepted")
	}
}
