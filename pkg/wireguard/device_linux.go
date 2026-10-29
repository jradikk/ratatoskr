//go:build linux

// Package wireguard manages kernel WireGuard identities and authenticated
// peers. Private keys remain in the creating network namespace's kernel and
// short-lived process memory; callers must never put them in API objects.
package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Port interprets zero as the shared default without requiring a defaulting
// webhook (the init and gateway both run in their own pod network namespace).
func Port(configured uint16) int {
	if configured == 0 {
		return 51820
	}
	return int(configured)
}

func PublicKey(name string) (string, error) {
	c, err := wgctrl.New()
	if err != nil {
		return "", err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return "", err
	}
	return dev.PublicKey.String(), nil
}
func Ensure(h *netlink.Handle, name string, listen uint16, mark uint32) (string, error) {
	link, err := h.LinkByName(name)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return "", err
		}
		if err := h.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			return "", fmt.Errorf("create WireGuard device: %w", err)
		}
		link, err = h.LinkByName(name)
		if err != nil {
			return "", err
		}
	}
	if link.Type() != "wireguard" {
		return "", fmt.Errorf("%s is not a WireGuard link", name)
	}
	c, err := wgctrl.New()
	if err != nil {
		return "", err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return "", err
	}
	config := wgtypes.Config{}
	if dev.PublicKey == (wgtypes.Key{}) {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", err
		}
		defer func() { key = wgtypes.Key{} }()
		config.PrivateKey = &key
	}
	p := Port(listen)
	m := int(mark)
	config.ListenPort = &p
	config.FirewallMark = &m
	if err := c.ConfigureDevice(name, config); err != nil {
		return "", fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := h.LinkSetUp(link); err != nil {
		return "", err
	}
	dev, err = c.Device(name)
	if err != nil {
		return "", err
	}
	if dev.PublicKey == (wgtypes.Key{}) {
		return "", fmt.Errorf("WireGuard device has no public key")
	}
	return dev.PublicKey.String(), nil
}
func parsedKey(s string) (wgtypes.Key, error) {
	key, err := wgtypes.ParseKey(s)
	if err != nil || key == (wgtypes.Key{}) {
		return key, fmt.Errorf("invalid WireGuard public key")
	}
	return key, nil
}
func validPeerIP(ip netip.Addr) error {
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("WireGuard peer must have unicast IPv4 pod IP")
	}
	return nil
}
func host(ip netip.Addr) net.IPNet {
	v := ip.As4()
	return net.IPNet{IP: net.IP(v[:]), Mask: net.CIDRMask(32, 32)}
}

// ClientPeer pins the gateway PodIP to its authenticated public key. Endpoint
// (UDP transport) and AllowedIPs (GENEVE outer destination) use the same IP.
func ClientPeer(name string, remote netip.Addr, keyString string, port uint16) error {
	if err := validPeerIP(remote); err != nil {
		return err
	}
	key, err := parsedKey(keyString)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	dst := remote.As4()
	return c.ConfigureDevice(name, wgtypes.Config{ReplacePeers: true, Peers: []wgtypes.PeerConfig{{PublicKey: key, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{host(remote)}, Endpoint: &net.UDPAddr{IP: net.IP(dst[:]), Port: Port(port)}}}})
}

// GatewayPeer is called only after the caller authenticates a Pod-bound token.
// It never infers peers from a controller's desired GENEVE client list.
func GatewayPeer(name string, clientIP netip.Addr, keyString string) error {
	if err := validPeerIP(clientIP); err != nil {
		return err
	}
	key, err := parsedKey(keyString)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return err
	}
	for _, peer := range dev.Peers {
		if peer.PublicKey == key {
			continue
		}
		for _, allowed := range peer.AllowedIPs {
			if allowed.Contains(net.IP(clientIP.AsSlice())) && len(allowed.Mask) == 4 && allowed.Mask.String() == net.CIDRMask(32, 32).String() {
				if err := c.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: peer.PublicKey, Remove: true}}}); err != nil {
					return err
				}
				break
			}
		}
	}
	return c.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{host(clientIP)}}}})
}
func RemoveGatewayPeer(name string, clientIP netip.Addr) error {
	if err := validPeerIP(clientIP); err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return err
	}
	for _, peer := range dev.Peers {
		for _, allowed := range peer.AllowedIPs {
			if allowed.Contains(net.IP(clientIP.AsSlice())) && len(allowed.Mask) == 4 && allowed.Mask.String() == net.CIDRMask(32, 32).String() {
				return c.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: peer.PublicKey, Remove: true}}})
			}
		}
	}
	return nil
}
func Remove(h *netlink.Handle, name string) error {
	link, err := h.LinkByName(name)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return err
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("%s is not a WireGuard link", name)
	}
	return h.LinkDel(link)
}

// ClearPeers withdraws all client peers when no gateway is healthy. It is
// deliberately not used on gateways, whose peers require explicit removal.
func ClearPeers(name string) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(name, wgtypes.Config{ReplacePeers: true})
}
