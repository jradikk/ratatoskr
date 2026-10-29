// Command gateway terminates unencrypted GENEVE and gates forwarding on upstream health.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/ebpf"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	gatewaydns "github.com/skaldhall/ratatoskr/pkg/dns"
	"github.com/skaldhall/ratatoskr/pkg/mtu"
	"github.com/skaldhall/ratatoskr/pkg/observability"
	"github.com/skaldhall/ratatoskr/pkg/platform"
	"github.com/skaldhall/ratatoskr/pkg/version"

	mdns "github.com/miekg/dns"
)

// gatewayMetricsAddr is private to the gateway pod's network namespace.
// A future Service/scraper must explicitly review authentication and policy.
const gatewayMetricsAddr = "127.0.0.1:9902"

// A private loopback endpoint in the shared pod network namespace is the only
// source of truth for VPN health and exit IP. The gateway publishes only cached
// readiness and the non-secret exit IP on its own port for probes/controller use.
type state struct {
	ready         bool
	exitIP        string
	upstreamIndex int
	podMTU        int
	geneveMTU     int
	wireguardMTU  int
	upstreamMTU   int
	effectiveMTU  int
	mss           int
}
type upstreamInfo struct {
	ExitIP string `json:"exitIP"`
	MTU    int    `json:"mtu"`
}

func probe(client *http.Client, encryption string) (state, error) {
	var s state
	resp, err := client.Get("http://127.0.0.1:9901/healthz")
	if err != nil {
		return s, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s, errors.New("upstream unhealthy")
	}
	resp, err = client.Get("http://127.0.0.1:9901/info")
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s, errors.New("upstream info unavailable")
	}
	var info upstreamInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&info); err != nil {
		return s, err
	}
	addr, err := netip.ParseAddr(info.ExitIP)
	if err != nil || !addr.Is4() || addr.IsUnspecified() {
		return s, errors.New("upstream exit IP invalid")
	}
	link, err := netlink.LinkByName(datapath.UpstreamDevice)
	if err != nil {
		return s, err
	}
	if link.Attrs().Flags&net.FlagUp == 0 || link.Attrs().MTU < mtu.MinInnerMTU {
		return s, errors.New("upstream link down or MTU too small")
	}
	eth, err := netlink.LinkByName("eth0")
	if err != nil {
		return s, fmt.Errorf("read gateway eth0: %w", err)
	}
	gnv, err := netlink.LinkByName(datapath.GatewayDevice)
	if err != nil {
		return s, fmt.Errorf("read gateway GENEVE MTU: %w", err)
	}
	s.podMTU = eth.Attrs().MTU
	s.geneveMTU = gnv.Attrs().MTU
	s.upstreamMTU = link.Attrs().MTU
	carrierMTU := s.podMTU
	if encryption == "wireguard" {
		wg, e := netlink.LinkByName("rtkwg0")
		if e != nil {
			return state{}, errors.New("WireGuard underlay unavailable")
		}
		s.wireguardMTU = wg.Attrs().MTU
		if s.wireguardMTU > s.podMTU-mtu.WireGuardOverhead(mtu.IPv4) {
			return state{}, errors.New("WireGuard MTU exceeds pod carrier")
		}
		carrierMTU = s.wireguardMTU
	}
	maxGeneve := carrierMTU - mtu.GeneveOverhead(mtu.IPv4, 0)
	if s.geneveMTU > maxGeneve {
		return state{}, errors.New("GENEVE MTU exceeds pod carrier MTU")
	}
	s.effectiveMTU = s.geneveMTU
	if s.upstreamMTU < s.effectiveMTU {
		s.effectiveMTU = s.upstreamMTU
	}
	if s.effectiveMTU < mtu.MinInnerMTU {
		return state{}, errors.New("gateway inner MTU below IPv4 minimum")
	}
	s.mss = s.effectiveMTU - 40
	s.ready = true
	s.exitIP = info.ExitIP
	s.upstreamIndex = link.Attrs().Index
	return s, nil
}

func gatewayInnerMTU(configMTU, podMTU int) (int, error) {
	return gatewayInnerMTUForMode(configMTU, podMTU, mtu.EncryptionNone)
}
func gatewayInnerMTUForMode(configMTU, podMTU int, encryption mtu.Encryption) (int, error) {
	computed, err := mtu.Compute(mtu.Params{PodMTU: podMTU, Underlay: mtu.IPv4, Encryption: encryption})
	if err != nil {
		return 0, err
	}
	if configMTU < mtu.MinInnerMTU {
		return 0, errors.New("gateway configured MTU below IPv4 minimum")
	}
	if configMTU < computed.GeneveMTU {
		return configMTU, nil
	}
	return computed.GeneveMTU, nil
}
func clampGatewayMTU(cfg *datapath.GatewayConfig) error {
	eth, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("look up gateway eth0: %w", err)
	}
	cfg.MTU, err = gatewayInnerMTUForMode(cfg.MTU, eth.Attrs().MTU, mtu.Encryption(cfg.Encryption))
	return err
}

func startGatewayDNS(listen string, ready func() bool, errorsCh chan<- error) (func(), error) {
	cluster, err := netip.ParseAddr(os.Getenv("CLUSTER_DNS_IP"))
	if err != nil {
		return nil, errors.New("CLUSTER_DNS_IP is required for gateway DNS")
	}
	upstream := netip.Addr{}
	if raw := os.Getenv("UPSTREAM_DNS_IP"); raw != "" {
		upstream, err = netip.ParseAddr(raw)
		if err != nil {
			return nil, errors.New("invalid UPSTREAM_DNS_IP")
		}
	}
	var cidrs []netip.Prefix
	for _, s := range strings.Split(os.Getenv("CLUSTER_CIDRS"), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() {
			return nil, errors.New("invalid CLUSTER_CIDRS for gateway DNS")
		}
		cidrs = append(cidrs, p.Masked())
	}
	f, err := gatewaydns.New(gatewaydns.Options{ClusterDNS: cluster, UpstreamDNS: upstream, ClusterDomain: os.Getenv("CLUSTER_DOMAIN"), ClusterCIDRs: cidrs, ExternalReady: ready})
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", listen)
	if err != nil {
		return nil, fmt.Errorf("listen gateway DNS/UDP: %w", err)
	}
	tcp, err := net.Listen("tcp4", listen)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listen gateway DNS/TCP: %w", err)
	}
	servers := []*mdns.Server{{PacketConn: udp, Net: "udp", Handler: f}, {Listener: tcp, Net: "tcp", Handler: f}}
	for _, srv := range servers {
		go func() {
			if e := srv.ActivateAndServe(); e != nil {
				select {
				case errorsCh <- fmt.Errorf("gateway DNS listener: %w", e):
				default:
				}
			}
		}()
	}
	return func() {
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
	}, nil
}

// readGatewayConfig loads non-secret ConfigMap data afresh so selected pod
// changes take effect without restarting the gateway pod. ConfigMap projection
// is atomic; a malformed replacement must make the gateway fail closed.
func readGatewayConfig(configPath string) (datapath.GatewayConfig, error) {
	var cfg datapath.GatewayConfig
	f, err := os.Open(configPath) // #nosec G304 -- explicit operator-owned ConfigMap mount, not an HTTP request path.
	if err != nil {
		return cfg, fmt.Errorf("open gateway config: %w", err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return cfg, err
	}
	if stat.Size() > 1<<20 {
		return cfg, errors.New("gateway config exceeds 1 MiB")
	}
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid gateway datapath config")
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cfg, errors.New("multiple gateway config documents are forbidden")
	}
	if !cfg.PodIP.IsValid() {
		cfg.PodIP, err = netip.ParseAddr(os.Getenv("POD_IP"))
		if err != nil {
			return cfg, errors.New("podIP config or POD_IP environment is required")
		}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// gatewayBackend rejects unknown and unavailable modes without falling back.
func gatewayBackend(mode string) (datapath.Backend, error) {
	switch mode {
	case "", "iproute":
		return iproute.New()
	case "ebpf":
		return ebpf.New()
	default:
		return nil, fmt.Errorf("unsupported DATAPATH %q", mode)
	}
}

func run(ctx context.Context, configPath string) error {
	if err := platform.CheckKernel(); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("-config is required")
	}
	cfg, err := readGatewayConfig(configPath)
	if err != nil {
		return err
	}
	if err := clampGatewayMTU(&cfg); err != nil {
		return err
	}
	backend, err := gatewayBackend(os.Getenv("DATAPATH"))
	if err != nil {
		return err
	}
	defer backend.Close()
	cfg.UpstreamHealthy = false
	if err := backend.ApplyGateway(ctx, cfg); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	server := &http.Server{Addr: ":9900", ReadHeaderTimeout: 3 * time.Second}
	var current atomic.Value
	current.Store(state{})
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !current.Load().(state).ready {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		s := current.Load().(state)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ExitIP       string `json:"exitIP"`
			Ready        bool   `json:"ready"`
			PodMTU       int    `json:"podMTU"`
			GeneveMTU    int    `json:"geneveMTU"`
			WireguardMTU int    `json:"wireguardMTU"`
			UpstreamMTU  int    `json:"upstreamMTU"`
			EffectiveMTU int    `json:"effectiveMTU"`
			MSS          int    `json:"mss"`
		}{s.exitIP, s.ready, s.podMTU, s.geneveMTU, s.wireguardMTU, s.upstreamMTU, s.effectiveMTU, s.mss})
	})
	server.Handler = mux
	// The health API remains on the pod network for probes/controller. Metrics
	// are deliberately bound to loopback only; do not add a public Service or
	// NetworkPolicy ingress without an explicit scrape-authentication design.
	metrics := &http.Server{Addr: gatewayMetricsAddr, Handler: observability.GatewayHandler(func() bool { return current.Load().(state).ready }), ReadHeaderTimeout: 3 * time.Second}
	metricsListener, err := net.Listen("tcp4", metrics.Addr)
	if err != nil {
		return fmt.Errorf("listen private gateway metrics: %w", err)
	}
	serverErrors := make(chan error, 2)
	go func() {
		if err := metrics.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case serverErrors <- fmt.Errorf("private gateway metrics: %w", err):
			default:
			}
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = metrics.Shutdown(shutdownCtx)
	}()
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen gateway health API: %w", err)
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case serverErrors <- fmt.Errorf("gateway health API: %w", err):
			default:
			}
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if cfg.Encryption == "wireguard" {
		// Registration requires the existing iproute WireGuard manager; never
		// allow an unsupported backend to publish plaintext readiness.
		wgBackend, ok := backend.(*iproute.Backend)
		if !ok {
			return errors.New("selected datapath does not support WireGuard registration")
		}
		stopRegistration, e := startEncryptedGateway(ctx, os.Getenv("GATEWAY_NAME"), cfg.PodIP, wgBackend, serverErrors)
		if e != nil {
			return e
		}
		defer stopRegistration()
	}
	if listen := os.Getenv("GATEWAY_DNS_LISTEN_ADDR"); listen != "" {
		stopDNS, e := startGatewayDNS(listen, func() bool { return current.Load().(state).ready }, serverErrors)
		if e != nil {
			return e
		}
		defer stopDNS()
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	prev := state{}
	for {
		next, readErr := readGatewayConfig(configPath)
		if readErr == nil {
			readErr = clampGatewayMTU(&next)
		}
		if readErr != nil {
			// A missing/invalid replacement must never keep using stale selected
			// pod permissions or an old upstream-ready accept rule.
			cfg.UpstreamHealthy = false
			cfg.Clients = nil
			current.Store(state{})
			prev = state{}
			if err := backend.ApplyGateway(ctx, cfg); err != nil {
				logger.Error("gateway fail-closed update failed", "error", err)
			}
			logger.Error("gateway config unavailable", "error", readErr)
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
				continue
			}
		}
		next.UpstreamHealthy = cfg.UpstreamHealthy
		changed := !reflect.DeepEqual(cfg, next)
		cfg = next
		s, err := probe(client, cfg.Encryption)
		if err != nil {
			s = state{}
		}
		// Even with no upstream, keep refreshing table 100 so it is installed as
		// soon as the plugin creates upstream0; marked recovery probes need it.
		if changed || s != prev || !s.ready {
			cfg.UpstreamHealthy = s.ready
			if err := backend.ApplyGateway(ctx, cfg); err != nil {
				s = state{}
				logger.Error("gateway datapath update failed", "error", err)
			}
			prev = s
			current.Store(s)
		}
		select {
		case <-ctx.Done():
			cfg.UpstreamHealthy = false
			_ = backend.ApplyGateway(context.Background(), cfg)
			return nil
		case err := <-serverErrors:
			cfg.UpstreamHealthy = false
			_ = backend.ApplyGateway(context.Background(), cfg)
			return fmt.Errorf("gateway health API failed: %w", err)
		case <-tick.C:
		}
	}
}
func main() { os.Exit(mainCode()) }

func mainCode() int {
	showVersion := flag.Bool("version", false, "print version and exit")
	config := flag.String("config", "", "non-secret gateway datapath JSON config")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-gateway", version.String())
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *config); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("gateway failed", "error", err)
		return 1
	}
	return 0
}
