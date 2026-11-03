//go:build linux && privileged

package agent

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestPrivilegedDualStackKeepsIPv4WithoutQuarantine(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_SYS_ADMIN/NET_ADMIN")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	sandbox, err := netns.New()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("CAP_SYS_ADMIN unavailable for isolated netns")
		}
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatalf("restore original netns: %v", err)
		}
		_ = sandbox.Close()
	}()
	eth := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", MTU: 1500}}
	if err := netlink.LinkAdd(eth); err != nil {
		t.Fatal(err)
	}
	if err := inspectAndGuard(); err != nil {
		t.Fatal(err)
	}
	eth, err = func() (*netlink.Dummy, error) {
		l, e := netlink.LinkByName("eth0")
		if e != nil {
			return nil, e
		}
		v, ok := l.(*netlink.Dummy)
		if !ok {
			return nil, errors.New("eth0 is not dummy")
		}
		return v, nil
	}()
	if err != nil {
		t.Fatal(err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)}}
	if err := netlink.AddrAdd(eth, addr); err != nil {
		t.Fatal(err)
	}
	if err := inspectAndGuard(); err != nil {
		t.Fatalf("dual-stack IPv4 was refused: %v", err)
	}
	blocked, err := quarantined()
	if err != nil || blocked {
		t.Fatalf("dual-stack address installed IPv4 quarantine: %t %v", blocked, err)
	}
	if err := netlink.AddrDel(eth, addr); err != nil {
		t.Fatal(err)
	}
	if err := inspectAndGuard(); err != nil {
		t.Fatalf("removing IPv6 address changed IPv4 guard state: %v", err)
	}
}
