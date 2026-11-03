//go:build linux && privileged

package agent

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// A disposable two-netns component exercises the exact thread restoration
// path with an agent namespace distinct from both the host anchor and target.
// No host or cluster network namespace is modified.
func TestPrivilegedSeparateAgentNamespaceRestoration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_SYS_ADMIN")
	}
	if verifiedNamespaces.Load() != nil {
		t.Skip("process anchor already established")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	agentNS, err := netns.New()
	if errors.Is(err, unix.EPERM) {
		t.Skip("CAP_SYS_ADMIN unavailable for separate agent namespace")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(original); err != nil {
			panic(err)
		}
		_ = agentNS.Close()
	}()
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	hostFD, err := unix.Dup(int(original))
	if err != nil {
		t.Fatal(err)
	}
	host := os.NewFile(uintptr(hostFD), "original-test-netns")
	defer host.Close()
	anchor, err := validateAnchors(own, host)
	if err != nil {
		t.Fatal(err)
	}
	verifiedNamespaces.Store(anchor)
	defer verifiedNamespaces.Store(nil)
	if err := checkThreadOwn(); err != nil {
		t.Fatal(err)
	}
	if a, h, err := anchorStats(); err != nil || sameNetns(a, h) {
		t.Fatalf("own and host anchors not distinct: %v", err)
	}
	if err := rejectHost(own); err == nil {
		t.Fatal("accepted agent namespace as selected workload")
	}
	if err := rejectHost(host); err == nil {
		t.Fatal("accepted host anchor as selected workload")
	}
	targetNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer targetNS.Close()
	if err := netns.Set(agentNS); err != nil {
		t.Fatal(err)
	}
	target := os.NewFile(uintptr(targetNS), "disposable-target-netns")
	entered := false
	if err := InNamespace(target, func() error {
		entered = true
		if err := checkThreadOwn(); err == nil {
			return errors.New("target namespace mistaken for agent namespace")
		}
		return nil
	}); err != nil || !entered {
		t.Fatalf("target entry failed: %t %v", entered, err)
	}
	if err := checkThreadOwn(); err != nil {
		t.Fatalf("thread was not restored to agent namespace: %v", err)
	}
	failure := errors.New("selected namespace operation failed")
	if err := InNamespace(target, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("selected operation error changed: %v", err)
	}
	if err := checkThreadOwn(); err != nil {
		t.Fatalf("failed operation left thread outside agent namespace: %v", err)
	}
}
