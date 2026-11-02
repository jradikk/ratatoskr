//go:build linux

package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSampleDeviceKernelAggregateAndUnknownHandshake(t *testing.T) {
	now := time.Unix(1000, 0)
	endpoint := netip.MustParseAddr("10.0.0.1")
	_ = endpoint // no endpoint address is included in exported samples.
	key, _ := wgtypes.GeneratePrivateKey()
	device := &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: key.PublicKey(), ReceiveBytes: 7, TransmitBytes: 11}, {ReceiveBytes: 5, TransmitBytes: 3, LastHandshakeTime: now.Add(-10 * time.Second)}}}
	sample, err := SampleDevice(context.Background(), "rtkwg0", now, func(string) (*wgtypes.Device, error) { return device, nil })
	if err != nil || sample.InstalledPeers != 2 || sample.HandshakenPeers != 1 || sample.LatestHandshakeAgeSeconds != 10 || sample.ReceiveBytes != 12 || sample.TransmitBytes != 14 {
		t.Fatalf("unexpected measured kernel aggregate: %+v %v", sample, err)
	}
	device.Peers = nil
	sample, err = SampleDevice(context.Background(), "rtkwg0", now, func(string) (*wgtypes.Device, error) { return device, nil })
	if err != nil || sample.InstalledPeers != 0 || sample.LatestHandshakeAgeSeconds != -1 {
		t.Fatalf("known zero peers not represented: %+v %v", sample, err)
	}
	_, err = SampleDevice(context.Background(), "rtkwg0", now, func(string) (*wgtypes.Device, error) { return nil, errors.New("device unavailable") })
	if err == nil {
		t.Fatal("unknown kernel sample accepted as known zero")
	}
}
func TestSampleDeviceRespectsBoundedDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	_, err := SampleDevice(ctx, "rtkwg0", time.Now(), func(string) (*wgtypes.Device, error) { <-done; return &wgtypes.Device{}, nil })
	close(done)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("sample deadline ignored: %v", err)
	}
}
