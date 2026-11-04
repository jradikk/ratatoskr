//go:build linux && privileged

package main

import (
	"context"
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Verify real HTTP socket options in a disposable netns without connecting to
// the internet or touching host routing/conntrack.
func TestPrivilegedGeoTransportPinsUpstreamInterfaceAndRouteMark(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	target, err := netns.New()
	if errors.Is(err, unix.EPERM) {
		t.Skip("no disposable netns capability")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Error(err)
		}
		_ = target.Close()
	}()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: datapath.UpstreamDevice}}
	if err = netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	verified := false
	dialer := &net.Dialer{Timeout: time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		if err := geoSocketControl(network, address, raw); err != nil {
			return err
		}
		var check error
		if err := raw.Control(func(fd uintptr) {
			device, e := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
			if e != nil {
				check = e
				return
			}
			mark, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
			if e != nil {
				check = e
				return
			}
			if device != datapath.UpstreamDevice || mark != int(datapath.ProbeMark) {
				check = errors.New("geolocation socket escaped upstream device or probe route mark")
			}
		}); err != nil {
			return err
		}
		if check != nil {
			return check
		}
		verified = true
		return errors.New("test socket validated; refuse connect")
	}}
	_, err = dialer.DialContext(context.Background(), "tcp4", "198.19.0.1:443")
	if !verified || err == nil {
		t.Fatalf("socket options not pinned before attempted connect: verified=%t err=%v", verified, err)
	}
}
