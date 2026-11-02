// Package dns forwards gateway-mode workload DNS without changing pod DNS or
// the gateway pod's main route. Cluster names use kube-dns; external names use
// a marked, interface-bound socket in the upstream tunnel and never fall back.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// Options is an operator-owned, non-secret DNS configuration. A failure to
// resolve through the upstream is answered SERVFAIL, never retried on eth0.
type Options struct {
	ClusterDNS    netip.Addr
	UpstreamDNS   netip.Addr
	ClusterDomain string
	ClusterCIDRs  []netip.Prefix
	ExternalReady func() bool
}

type exchangeFunc func(context.Context, *mdns.Msg, string, bool, string) (*mdns.Msg, error)

type Forwarder struct {
	opts     Options
	exchange exchangeFunc
}

func New(opts Options) (*Forwarder, error) {
	if !opts.ClusterDNS.Is4() || opts.ClusterDNS.IsUnspecified() || opts.ClusterDNS.IsMulticast() {
		return nil, errors.New("cluster DNS must be an IPv4 service address")
	}
	if !opts.UpstreamDNS.IsValid() {
		opts.UpstreamDNS = netip.MustParseAddr("1.1.1.1")
	}
	if !opts.UpstreamDNS.Is4() || opts.UpstreamDNS.IsUnspecified() || opts.UpstreamDNS.IsMulticast() {
		return nil, errors.New("upstream DNS must be a unicast IPv4 address")
	}
	if opts.ClusterDomain == "" {
		opts.ClusterDomain = "cluster.local"
	}
	opts.ClusterDomain = strings.Trim(strings.ToLower(opts.ClusterDomain), ".")
	if opts.ClusterDomain == "" || strings.ContainsAny(opts.ClusterDomain, " /\\:") {
		return nil, errors.New("invalid cluster DNS domain")
	}
	if len(opts.ClusterCIDRs) == 0 {
		return nil, errors.New("cluster DNS requires pod/service CIDRs")
	}
	for _, p := range opts.ClusterCIDRs {
		if !p.IsValid() || !p.Addr().Is4() {
			return nil, errors.New("cluster DNS CIDRs must be IPv4")
		}
	}
	if opts.ExternalReady == nil {
		return nil, errors.New("upstream readiness callback is required")
	}
	return &Forwarder{opts: opts, exchange: exchange}, nil
}

func (f *Forwarder) isClusterName(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	if n == f.opts.ClusterDomain || strings.HasSuffix(n, "."+f.opts.ClusterDomain) {
		return true
	}
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(n, suffix) {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(n, suffix), ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	var ip [4]byte
	for i, part := range parts {
		octet, err := strconv.Atoi(part)
		if err != nil || octet < 0 || octet > 255 {
			return false
		}
		ip[len(parts)-1-i] = byte(octet)
	}
	// An in-addr.arpa delegation can contain 1..4 reversed octets. Route
	// partially specified zones to kube-dns only if they overlap a cluster
	// prefix; otherwise they must not expose cluster topology externally.
	candidate := netip.PrefixFrom(netip.AddrFrom4(ip), 8*len(parts))
	for _, p := range f.opts.ClusterCIDRs {
		if p.Overlaps(candidate) {
			return true
		}
	}
	return false
}
func (f *Forwarder) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	if len(req.Question) != 1 || req.Opcode != mdns.OpcodeQuery {
		reject(w, req, mdns.RcodeFormatError)
		return
	}
	cluster := f.isClusterName(req.Question[0].Name)
	if !cluster && !f.opts.ExternalReady() {
		reject(w, req, mdns.RcodeServerFailure)
		return
	}
	target := f.opts.UpstreamDNS
	if cluster {
		target = f.opts.ClusterDNS
	}
	protocol := "udp"
	if w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp") {
		protocol = "tcp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	answer, err := f.exchange(ctx, req, net.JoinHostPort(target.String(), "53"), !cluster, protocol)
	if err != nil || answer == nil {
		reject(w, req, mdns.RcodeServerFailure)
		return
	}
	answer.Id = req.Id
	_ = w.WriteMsg(answer)
}
func reject(w mdns.ResponseWriter, req *mdns.Msg, rcode int) {
	m := new(mdns.Msg)
	m.SetRcode(req, rcode)
	_ = w.WriteMsg(m)
}

func exchange(ctx context.Context, req *mdns.Msg, addr string, upstream bool, protocol string) (*mdns.Msg, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if upstream {
		// Applying both options is mandatory; no alternate/unbound fallback.
		d.Control = func(network, address string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, datapath.UpstreamDevice)
				if sockErr == nil {
					sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(datapath.ProbeMark))
				}
			}); err != nil {
				return err
			}
			return sockErr
		}
	}
	client := &mdns.Client{Net: protocol, Timeout: 3 * time.Second, Dialer: d}
	out, _, err := client.ExchangeContext(ctx, req, addr)
	if err != nil {
		return nil, fmt.Errorf("DNS upstream unavailable: %w", err)
	}
	return out, nil
}
