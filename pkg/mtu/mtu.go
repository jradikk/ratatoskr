// Package mtu computes tunnel MTUs and TCP MSS values for the Ratatoskr datapath.
//
// Packet layering on the client → gateway leg (outermost first):
//
//	encryption: none       pod eth0 | IP | UDP 6081 | GENEVE+TLVs | Ethernet | inner IP ...
//	encryption: wireguard  pod eth0 | IP | UDP | WG | IP | UDP 6081 | GENEVE+TLVs | Ethernet | inner IP ...
//
// The Linux GENEVE device carries Ethernet frames, so its overhead includes the
// inner Ethernet header. On the gateway the decapsulated packet then leaves via
// the upstream tunnel, so the usable end-to-end MTU is also bounded by upstream0.
package mtu

import (
	"errors"
	"fmt"
)

// Family is the address family of an outer (underlay) header.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

// Encryption selects the optional underlay below GENEVE.
type Encryption string

const (
	EncryptionNone      Encryption = "none"
	EncryptionWireGuard Encryption = "wireguard"
)

const (
	ipv4Header     = 20
	ipv6Header     = 40
	udpHeader      = 8
	ethernetHeader = 14
	geneveBase     = 8
	// WireGuard transport data message: type(4) + receiver(4) + counter(8) + Poly1305 tag(16).
	wireguardHeader = 32
	tcpHeader       = 20

	// MaxTLVBytes is the largest GENEVE options length (6-bit field in 4-byte units).
	MaxTLVBytes = 63 * 4
	// MinInnerMTU is the floor below which we refuse to program a datapath (IPv4 minimum).
	MinInnerMTU = 576
	// IPv6MinMTU is reported as a warning threshold; IPv6 is a v1 non-goal but planned.
	IPv6MinMTU = 1280
)

func ipHeader(f Family) int {
	if f == IPv6 {
		return ipv6Header
	}
	return ipv4Header
}

// GeneveOverhead is the bytes GENEVE adds on top of an inner L3 packet.
func GeneveOverhead(outer Family, tlvBytes int) int {
	return ipHeader(outer) + udpHeader + geneveBase + tlvBytes + ethernetHeader
}

// WireGuardOverhead is the bytes WireGuard adds on top of the packet it carries.
func WireGuardOverhead(outer Family) int {
	return ipHeader(outer) + udpHeader + wireguardHeader
}

// Params are the inputs to Compute.
type Params struct {
	// PodMTU is the MTU of the pod's eth0 as set by the CNI.
	PodMTU int
	// Underlay is the address family of the pod network.
	Underlay Family
	// Encryption is the per-gateway underlay mode.
	Encryption Encryption
	// TLVBytes is the total GENEVE options length including option headers
	// (0 for the iproute datapath, which sends no options).
	TLVBytes int
	// UpstreamMTU is the gateway's upstream0 MTU; 0 means unknown.
	UpstreamMTU int
}

// Result holds the computed values.
type Result struct {
	// WireGuardMTU is the MTU for the WireGuard device (0 when unencrypted).
	WireGuardMTU int `json:"wireguardMTU,omitempty"`
	// GeneveMTU is the MTU for the GENEVE device.
	GeneveMTU int `json:"geneveMTU"`
	// EffectiveMTU is the end-to-end inner MTU including the upstream tunnel.
	EffectiveMTU int `json:"effectiveMTU"`
	// MSS is the TCP MSS to clamp to for IPv4 inner traffic.
	MSS int `json:"mss"`
	// Warnings are non-fatal observations (e.g. MTU below the IPv6 minimum).
	Warnings []string `json:"warnings,omitempty"`
}

// Compute derives tunnel MTUs and MSS from p.
func Compute(p Params) (Result, error) {
	var r Result
	if p.PodMTU <= 0 {
		return r, errors.New("pod MTU must be positive")
	}
	if p.Underlay != IPv4 && p.Underlay != IPv6 {
		return r, fmt.Errorf("unknown underlay family %d", p.Underlay)
	}
	if p.TLVBytes < 0 || p.TLVBytes%4 != 0 || p.TLVBytes > MaxTLVBytes {
		return r, fmt.Errorf("GENEVE TLV length %d must be a multiple of 4 in [0,%d]", p.TLVBytes, MaxTLVBytes)
	}
	if p.UpstreamMTU < 0 {
		return r, errors.New("upstream MTU must not be negative")
	}

	carrier := p.PodMTU
	geneveOuter := p.Underlay
	switch p.Encryption {
	case EncryptionNone, "":
	case EncryptionWireGuard:
		r.WireGuardMTU = p.PodMTU - WireGuardOverhead(p.Underlay)
		carrier = r.WireGuardMTU
		// GENEVE peers address each other by their WireGuard overlay IPs (IPv4 in v1).
		geneveOuter = IPv4
	default:
		return r, fmt.Errorf("unknown encryption %q", p.Encryption)
	}

	r.GeneveMTU = carrier - GeneveOverhead(geneveOuter, p.TLVBytes)
	r.EffectiveMTU = r.GeneveMTU
	if p.UpstreamMTU > 0 && p.UpstreamMTU < r.EffectiveMTU {
		r.EffectiveMTU = p.UpstreamMTU
	}
	if r.EffectiveMTU < MinInnerMTU {
		return r, fmt.Errorf("effective inner MTU %d is below the minimum %d (pod MTU %d, encryption %s, TLV %d, upstream %d)",
			r.EffectiveMTU, MinInnerMTU, p.PodMTU, p.Encryption, p.TLVBytes, p.UpstreamMTU)
	}
	if r.EffectiveMTU < IPv6MinMTU {
		r.Warnings = append(r.Warnings, fmt.Sprintf("effective MTU %d is below the IPv6 minimum of %d", r.EffectiveMTU, IPv6MinMTU))
	}
	r.MSS = r.EffectiveMTU - ipv4Header - tcpHeader
	return r, nil
}
