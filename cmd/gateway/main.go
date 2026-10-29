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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/version"
)

// A private loopback endpoint in the shared pod network namespace is the only
// source of truth for VPN health and exit IP. The gateway publishes only cached
// readiness and the non-secret exit IP on its own port for probes/controller use.
type state struct {
	ready         bool
	exitIP        string
	upstreamIndex int
	upstreamMTU   int
}
type upstreamInfo struct {
	ExitIP string `json:"exitIP"`
	MTU    int    `json:"mtu"`
}

func probe(client *http.Client) (state, error) {
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
	if link.Attrs().Flags&net.FlagUp == 0 || link.Attrs().MTU < 576 {
		return s, errors.New("upstream link down")
	}
	s.ready = true
	s.exitIP = info.ExitIP
	s.upstreamIndex = link.Attrs().Index
	s.upstreamMTU = link.Attrs().MTU
	return s, nil
}
func run(ctx context.Context, configPath string) error {
	if configPath == "" {
		return errors.New("-config is required")
	}
	f, err := os.Open(configPath) // #nosec G304 -- explicit administrator-supplied datapath configuration, not a request path.
	if err != nil {
		return fmt.Errorf("open gateway config: %w", err)
	}
	defer f.Close()
	var cfg datapath.GatewayConfig
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("decode gateway config: %w", err)
	}
	if !cfg.PodIP.IsValid() {
		cfg.PodIP, err = netip.ParseAddr(os.Getenv("POD_IP"))
		if err != nil {
			return errors.New("podIP config or POD_IP environment is required")
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	backend, err := iproute.New()
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
			ExitIP string `json:"exitIP"`
			Ready  bool   `json:"ready"`
		}{s.exitIP, s.ready})
	})
	server.Handler = mux
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen gateway health API: %w", err)
	}
	serverErrors := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	prev := state{}
	for {
		s, err := probe(client)
		if err != nil {
			s = state{}
		}
		// Even with no upstream, keep refreshing table 100 so it is installed as
		// soon as the plugin creates upstream0; marked recovery probes need it.
		if s != prev || !s.ready {
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
