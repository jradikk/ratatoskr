//go:build linux

package wireguard

import (
	"context"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerSample contains only aggregates measured from the live kernel device.
// A zero handshake count is known, not a claim that a peer is healthy.
type PeerSample struct {
	InstalledPeers            int
	HandshakenPeers           int
	LatestHandshakeAgeSeconds float64 // -1 means no peer has ever handshaken.
	ReceiveBytes              int64   // Current kernel peer sum; may decrease on peer removal.
	TransmitBytes             int64
}

// DeviceReader can be injected in tests; production reads the WireGuard kernel
// device through wgctrl. No per-peer key, IP, identity, or token is exported.
type DeviceReader func(name string) (*wgtypes.Device, error)

func KernelDevice(name string) (*wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Device(name)
}

// SampleDevice honors the request context before and after a bounded caller
// operation. wgctrl does not expose a cancellable Device call: a timeout
// returns unknown immediately while its in-flight read finishes separately.
// This must be called with a bounded context and limited concurrency.
func SampleDevice(ctx context.Context, name string, now time.Time, read DeviceReader) (PeerSample, error) {
	if err := ctx.Err(); err != nil {
		return PeerSample{}, err
	}
	if read == nil {
		return PeerSample{}, fmt.Errorf("WireGuard device reader required")
	}
	type result struct {
		device *wgtypes.Device
		err    error
	}
	done := make(chan result, 1)
	go func() { d, err := read(name); done <- result{d, err} }()
	select {
	case <-ctx.Done():
		return PeerSample{}, ctx.Err()
	case got := <-done:
		if err := ctx.Err(); err != nil {
			return PeerSample{}, err
		}
		if got.err != nil {
			return PeerSample{}, got.err
		}
		if got.device == nil {
			return PeerSample{}, fmt.Errorf("WireGuard device unavailable")
		}
		sample := PeerSample{InstalledPeers: len(got.device.Peers), LatestHandshakeAgeSeconds: -1}
		for _, peer := range got.device.Peers {
			sample.ReceiveBytes += peer.ReceiveBytes
			sample.TransmitBytes += peer.TransmitBytes
			if peer.LastHandshakeTime.IsZero() {
				continue
			}
			sample.HandshakenPeers++
			age := now.Sub(peer.LastHandshakeTime).Seconds()
			if age < 0 {
				age = 0
			}
			if sample.LatestHandshakeAgeSeconds < 0 || age < sample.LatestHandshakeAgeSeconds {
				sample.LatestHandshakeAgeSeconds = age
			}
		}
		return sample, nil
	}
}
