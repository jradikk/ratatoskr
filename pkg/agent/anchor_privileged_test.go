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

// Disposable netns exercise own-namespace restoration. The test host namespace
// is not used as a target and no cluster or existing host netns is mutated.
func TestPrivilegedSeparateAgentNamespaceRestoration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_SYS_ADMIN")
	}
	if verifiedOwn.Load() != nil {
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
	anchor, err := validateOwnAnchor(own)
	if err != nil {
		t.Fatal(err)
	}
	verifiedOwn.Store(anchor)
	defer verifiedOwn.Store(nil)
	if err := checkThreadOwn(); err != nil {
		t.Fatal(err)
	}
	if err := rejectOwn(own); err == nil {
		t.Fatal("accepted agent namespace as target")
	}
	targetNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer targetNS.Close()
	if err := netns.Set(agentNS); err != nil {
		t.Fatal(err)
	}
	// os.File owns its descriptor and may close it from a finalizer. Duplicate
	// the namespace handle so its lifetime cannot close a later reused FD.
	targetFD, err := unix.FcntlInt(uintptr(targetNS), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	target := os.NewFile(uintptr(targetFD), "disposable-target-netns")
	defer target.Close()
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
