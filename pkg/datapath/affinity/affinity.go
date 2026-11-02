// Package affinity selects a stable gateway endpoint for each pod without
// coupling policy or backend implementations to a particular controller.
package affinity

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
)

// Endpoint is a healthy gateway PodIP with a positive relative weight.
// Select uses unit weights; SelectWeighted supports unequal replica weights.
type Endpoint struct {
	IP     netip.Addr
	Weight uint32
}

// Select performs equal-weight rendezvous hashing over healthy IPv4 endpoints.
// The input order (including duplicate endpoints) cannot change the choice.
// An empty set is an error: callers must not fall through to a baseline route.
func Select(uid string, endpoints []netip.Addr) (netip.Addr, error) {
	weighted := make([]Endpoint, len(endpoints))
	for i, ip := range endpoints {
		weighted[i] = Endpoint{IP: ip, Weight: 1}
	}
	return SelectWeighted(uid, weighted)
}

// SelectWeighted uses the exponential race form of weighted rendezvous:
// each endpoint's score is -ln(U)/weight, and the lowest score wins. U is a
// reproducible SHA-256-derived uniform value in (0,1]. Adding or removing an
// endpoint cannot change the relative ranking of endpoints that remain.
func SelectWeighted(uid string, endpoints []Endpoint) (netip.Addr, error) {
	if uid == "" {
		return netip.Addr{}, fmt.Errorf("pod UID must not be empty")
	}
	if len(endpoints) == 0 {
		return netip.Addr{}, fmt.Errorf("no healthy gateway endpoints")
	}

	seen := make(map[netip.Addr]uint32, len(endpoints))
	var winner netip.Addr
	best := math.Inf(1)
	for _, endpoint := range endpoints {
		ip := endpoint.IP
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return netip.Addr{}, fmt.Errorf("gateway endpoint must be a unicast, routable IPv4 PodIP: %s", ip)
		}
		if endpoint.Weight == 0 {
			return netip.Addr{}, fmt.Errorf("gateway endpoint %s has zero weight", ip)
		}
		if old, ok := seen[ip]; ok {
			if old != endpoint.Weight {
				return netip.Addr{}, fmt.Errorf("gateway endpoint %s has conflicting weights", ip)
			}
			continue
		}
		seen[ip] = endpoint.Weight

		// Length-prefix the UID so its bytes cannot be confused with the
		// endpoint; use IP bytes, not user-supplied string formatting.
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(uid)))
		h := sha256.New()
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(uid))
		v := ip.As4()
		_, _ = h.Write(v[:])
		sum := h.Sum(nil)
		u := math.Ldexp(float64(binary.BigEndian.Uint64(sum[:8]))+1, -64)
		score := -math.Log(u) / float64(endpoint.Weight)
		if score < best || score == best && (!winner.IsValid() || ip.Less(winner)) {
			best, winner = score, ip
		}
	}
	return winner, nil
}
