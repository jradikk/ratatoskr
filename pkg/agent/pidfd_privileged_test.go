//go:build linux && privileged

package agent

import (
	"errors"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// A disposable namespace exercises the selected-PodIP guard and checks that a
// mismatched address is refused without changing any nft or routing state.
func TestPrivilegedCRIPathPodIPMismatch(t *testing.T) {
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
	if errors.Is(err, unix.EPERM) {
		t.Skip("CAP_SYS_ADMIN unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer sandbox.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			panic(err)
		}
	}()
	eth := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}
	if err := netlink.LinkAdd(eth); err != nil {
		t.Fatal(err)
	}
	ethLink, err := netlink.LinkByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("10.10.0.2/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(ethLink, addr); err != nil {
		t.Fatal(err)
	}
	if err := verifyTargetPodIPv4(netip.MustParseAddr("10.10.0.3")); err == nil {
		t.Fatal("accepted wrong PodIP")
	}
	if err := verifyTargetPodIPv4(netip.MustParseAddr("10.10.0.2")); err != nil {
		t.Fatal(err)
	}
	// A host-like secondary physical interface with its own IPv4 must not
	// pass even when a malicious namespace reports the expected eth0 PodIP.
	extra := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ens5"}}
	if err := netlink.LinkAdd(extra); err != nil {
		t.Fatal(err)
	}
	ens, err := netlink.LinkByName("ens5")
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := netlink.ParseAddr("192.0.2.11/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(ens, secondary); err != nil {
		t.Fatal(err)
	}
	if err := verifyTargetPodIPv4(netip.MustParseAddr("10.10.0.2")); err == nil {
		t.Fatal("host-like secondary interface accepted")
	}
}
