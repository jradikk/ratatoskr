// Command init programs the client netns before the workload starts (M1/M2).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/ebpf"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/mtu"
	"github.com/skaldhall/ratatoskr/pkg/platform"
	"github.com/skaldhall/ratatoskr/pkg/registration"
	"github.com/skaldhall/ratatoskr/pkg/version"
)

// completeConfig resolves values unavailable until CNI setup. The admission
// annotation intentionally omits the pod IP and MTU; the Downward API and eth0
// are authoritative after the init container enters the pod netns.
func completeConfig(cfg *datapath.ClientConfig, podIP string, podMTU int) error {
	if !cfg.PodIP.IsValid() {
		addr, err := netip.ParseAddr(podIP)
		if err != nil {
			return errors.New("POD_IP is required for injected datapath config")
		}
		cfg.PodIP = addr
	}
	if cfg.MTU == 0 {
		result, err := mtu.Compute(mtu.Params{PodMTU: podMTU, Underlay: mtu.IPv4, Encryption: mtu.Encryption(cfg.Encryption)})
		if err != nil {
			return fmt.Errorf("compute client MTU: %w", err)
		}
		cfg.MTU = result.GeneveMTU
	}
	if cfg.Identity.UID == "" {
		cfg.Identity.UID = os.Getenv("POD_UID")
	}
	if cfg.Identity.Pod == "" {
		cfg.Identity.Pod = os.Getenv("POD_NAME")
	}
	if cfg.Identity.Namespace == "" {
		cfg.Identity.Namespace = os.Getenv("POD_NAMESPACE")
	}
	return cfg.Validate()
}

// initBackend selects a backend without silently falling back to iproute.
func initBackend(mode string) (datapath.Backend, error) {
	switch mode {
	case "", "iproute":
		return iproute.New()
	case "ebpf":
		return ebpf.New()
	default:
		return nil, fmt.Errorf("unsupported DATAPATH %q", mode)
	}
}

func run(configPath string, remove bool) error {
	if err := platform.CheckKernel(); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("-config is required")
	}
	f, err := os.Open(configPath) // #nosec G304 -- explicit administrator-supplied datapath configuration, not a request path.
	if err != nil {
		return fmt.Errorf("open datapath config: %w", err)
	}
	defer f.Close()
	var cfg datapath.ClientConfig
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return fmt.Errorf("decode datapath config: %w", err)
	}
	podMTU := 0
	if cfg.MTU == 0 {
		link, linkErr := netlink.LinkByName("eth0")
		if linkErr != nil {
			return fmt.Errorf("look up pod eth0 MTU: %w", linkErr)
		}
		podMTU = link.Attrs().MTU
	}
	if err := completeConfig(&cfg, os.Getenv("POD_IP"), podMTU); err != nil {
		return err
	}
	backend, err := initBackend(os.Getenv("DATAPATH"))
	if err != nil {
		return err
	}
	defer backend.Close()
	if remove {
		return backend.RemoveClient(context.Background(), cfg)
	}
	if cfg.Encryption == "wireguard" && cfg.Endpoint.IsValid() {
		manager, ok := backend.(datapath.WireGuardManager)
		if !ok {
			return errors.New("selected datapath does not support WireGuard; refusing registration")
		}
		pub, err := manager.PrepareClientWireGuard(context.Background(), cfg)
		if err != nil {
			return fmt.Errorf("prepare WireGuard client: %w", err)
		}
		if err := registration.RegisterClient(context.Background(), registration.ClientRequest{
			GatewayPodIP: cfg.Endpoint, RegistrationCACert: []byte(cfg.RegistrationCACert), ClientPublicKey: pub,
			ProjectedTokenPath: "/var/run/ratatoskr/wg-token/token", // #nosec G101 -- fixed projected volume path, not token contents.
			BypassMark:         datapath.WireGuardMark,
		}); err != nil {
			return fmt.Errorf("authenticate gateway peer: %w", err)
		}
	}
	return backend.ApplyClient(context.Background(), cfg)
}
func waitAgentExitCode(remove bool, configPath string) int {
	if remove || configPath != "" {
		fmt.Fprintln(os.Stderr, "wait-agent cannot program or remove datapath")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runWaitAgent(ctx); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("agent datapath not ready", "error", err)
		return 1
	}
	return 0
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "", "non-secret client datapath JSON config")
	remove := flag.Bool("remove", false, "explicitly remove steering for this pod")
	waitAgent := flag.Bool("wait-agent", false, "block unprivileged until node agent programs this Pod")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-init", version.String())
		return
	}
	if *waitAgent {
		os.Exit(waitAgentExitCode(*remove, *configPath))
	}
	if err := run(*configPath, *remove); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("client datapath programming failed", "error", err)
		os.Exit(1)
	}
}
