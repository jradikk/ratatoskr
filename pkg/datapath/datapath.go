// Package datapath defines the CNI-independent contract shared by node agents,
// init containers and gateways. Callers must enter the intended network namespace
// before constructing a backend, and pin that OS thread while programming it.
package datapath

import (
	"context"
	"fmt"
	"net/netip"
)

const (
	GenevePort                  = 6081
	ClientDevice                = "rtk0"
	GatewayDevice               = "gnv0"
	WireGuardDevice             = "rtkwg0"
	WireGuardTable              = 102
	WireGuardMark        uint32 = 0x00400000
	WireGuardPortDefault uint16 = 51820
	UpstreamDevice              = "upstream0"
	ClientMAC                   = "02:52:54:4b:00:01"
	GatewayMAC                  = "02:52:54:4b:00:02"
	GatewayTable                = 100
	ReturnTable                 = 101
	ProbeMark            uint32 = 0x00100000
	MarkMask             uint32 = 0x00f00000
	RulePriority                = 10000
	RouteProtocol               = 186
)

// Backend is implemented by iproute and ebpf. Neither CRDs nor the
// controller depend on backend-specific tunnel, routing or map representations.
type Backend interface {
	ApplyClient(context.Context, ClientConfig) error
	RemoveClient(context.Context, ClientConfig) error
	ApplyGateway(context.Context, GatewayConfig) error
	Close()
}

// WireGuardManager is an optional backend capability. Gateway peer registration
// is explicit and must follow caller-side Pod-bound TokenReview authorization;
// ApplyGateway intentionally never infers peers from its Clients list.
type WireGuardManager interface {
	PrepareClientWireGuard(context.Context, ClientConfig) (publicKey string, err error)
	WireGuardPublicKey() (string, error)
	RegisterPeer(context.Context, netip.Addr, netip.Addr, string) error
	UnregisterPeer(context.Context, netip.Addr) error
	// ClearGatewayPeers revokes kernel peers after a gateway process restart,
	// before new authenticated registrations can be served.
	ClearGatewayPeers(context.Context) error
}

type Port struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}
type Rule struct {
	CIDRs []netip.Prefix `json:"cidrs"`
	Ports []Port         `json:"ports,omitempty"`
}
type Policy struct {
	Mode         string         `json:"mode,omitempty"`
	Rules        []Rule         `json:"rules,omitempty"`
	ExcludeCIDRs []netip.Prefix `json:"excludeCIDRs,omitempty"`
}
type Identity struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	UID       string `json:"uid"`
	Policy    string `json:"policy,omitempty"`
}

// DomainBinding records agent-owned DNS-derived destinations by original policy
// rule index. Include bindings remain protected after TTL expiry; exclude
// bindings must expire back to the VPN. No domain names or credentials persist.
type DomainBinding struct {
	Rule      int        `json:"rule"`
	Address   netip.Addr `json:"address"`
	ExpiresAt int64      `json:"expiresAt"`
	Retained  bool       `json:"retained"`
}

type ClientConfig struct {
	PodIP     netip.Addr `json:"podIP"`
	GatewayID uint32     `json:"gatewayID"`
	// An invalid/absent Endpoint means no healthy gateway: keep only the
	// unreachable route rather than allowing a lookup to fall through to main.
	Endpoint           netip.Addr      `json:"endpoint,omitempty"`
	AllowCloudMetadata bool            `json:"allowCloudMetadata,omitempty"`
	Exclusions         []netip.Prefix  `json:"exclusions"`
	MTU                int             `json:"mtu"`
	Encryption         string          `json:"encryption,omitempty"`
	GatewayPublicKey   string          `json:"gatewayPublicKey,omitempty"`
	RegistrationCACert string          `json:"registrationCACert,omitempty"`
	WireGuardPort      uint16          `json:"wireGuardPort,omitempty"`
	Identity           Identity        `json:"identity"`
	Policy             Policy          `json:"policy"`
	DomainState        []DomainBinding `json:"domainState,omitempty"`
}
type GatewayConfig struct {
	PodIP           netip.Addr   `json:"podIP"`
	GatewayID       uint32       `json:"gatewayID"`
	Clients         []netip.Addr `json:"clients"`
	MTU             int          `json:"mtu"`
	Encryption      string       `json:"encryption,omitempty"`
	WireGuardPort   uint16       `json:"wireGuardPort,omitempty"`
	UpstreamHealthy bool         `json:"upstreamHealthy"`
}

func ClientTable(id uint32) int { return int(0x52540000 | (id & 0xffff)) }
func validateBase(ip netip.Addr, id uint32, mtu int, encryption string) error {
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("podIP must be a unicast IPv4 address")
	}
	if id == 0 || id > 0xffffff {
		return fmt.Errorf("gatewayID must be in 1..16777215")
	}
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("MTU must be in 576..65535")
	}
	if encryption != "" && encryption != "none" && encryption != "wireguard" {
		return fmt.Errorf("unsupported encryption %q", encryption)
	}
	return nil
}
func (c ClientConfig) Validate() error {
	if err := validateBase(c.PodIP, c.GatewayID, c.MTU, c.Encryption); err != nil {
		return err
	}
	if c.Encryption != "wireguard" && (c.GatewayPublicKey != "" || c.RegistrationCACert != "" || c.WireGuardPort != 0) {
		return fmt.Errorf("WireGuard fields require wireguard encryption")
	}
	if len(c.RegistrationCACert) >= 4096 {
		return fmt.Errorf("registration CA certificate exceeds 4095 bytes")
	}
	if c.Encryption == "wireguard" && c.Endpoint.IsValid() && (c.GatewayPublicKey == "" || c.RegistrationCACert == "") {
		return fmt.Errorf("healthy WireGuard endpoint requires gateway public key and registration CA certificate")
	}
	if c.Endpoint.IsValid() && (!c.Endpoint.Is4() || c.Endpoint.IsUnspecified() || c.Endpoint.IsMulticast() || c.Endpoint == c.PodIP) {
		return fmt.Errorf("endpoint must be a distinct unicast IPv4 address")
	}
	for _, p := range c.Exclusions {
		if !p.IsValid() || !p.Addr().Is4() {
			return fmt.Errorf("exclusions must be IPv4 CIDRs")
		}
	}
	if c.Policy.Mode != "" && c.Policy.Mode != "include" && c.Policy.Mode != "exclude" {
		return fmt.Errorf("unsupported policy mode %q", c.Policy.Mode)
	}
	if c.Policy.Mode == "" && len(c.Policy.Rules) > 0 {
		return fmt.Errorf("policy rules require include or exclude mode")
	}
	for _, p := range c.Policy.ExcludeCIDRs {
		if !p.IsValid() || !p.Addr().Is4() {
			return fmt.Errorf("policy exclusions must be IPv4 CIDRs")
		}
	}
	matches := 0
	for _, r := range c.Policy.Rules {
		for _, p := range r.CIDRs {
			if !p.IsValid() || !p.Addr().Is4() {
				return fmt.Errorf("policy destinations must be IPv4 CIDRs")
			}
		}
		for _, p := range r.Ports {
			if (p.Protocol != "TCP" && p.Protocol != "UDP") || p.Port == 0 {
				return fmt.Errorf("policy ports require TCP/UDP and a nonzero port")
			}
		}
		count := len(r.CIDRs)
		if count == 0 {
			count = 1
		}
		ports := len(r.Ports)
		if ports == 0 {
			ports = 1
		}
		matches += count * ports
		if matches > 4096 {
			return fmt.Errorf("policy exceeds 4096 destination/port matches")
		}
	}
	return nil
}
func (c GatewayConfig) Validate() error {
	if err := validateBase(c.PodIP, c.GatewayID, c.MTU, c.Encryption); err != nil {
		return err
	}
	if c.Encryption != "wireguard" && c.WireGuardPort != 0 {
		return fmt.Errorf("WireGuard port requires wireguard encryption")
	}
	seen := make(map[netip.Addr]bool)
	for _, ip := range c.Clients {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip == c.PodIP || seen[ip] {
			return fmt.Errorf("clients must contain distinct unicast IPv4 pod addresses")
		}
		seen[ip] = true
	}
	return nil
}
