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
