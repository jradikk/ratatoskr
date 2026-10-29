//go:build linux && privileged

package wireguard

import (
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestPrivilegedKernelWireGuard(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Error(err)
		}
		_ = ns.Close()
	}()
	h, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for i := 0; i < 2; i++ {
		key, err := Ensure(h, "rtkwg0", 51820, 0x00400000)
		if err != nil {
			t.Fatal(err)
		}
		if key == "" {
			t.Fatal("no public identity")
		}
	}
	if err := Remove(h, "rtkwg0"); err != nil {
		t.Fatal(err)
	}
}
