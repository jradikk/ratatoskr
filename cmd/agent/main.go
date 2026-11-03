// Command agent programs pod network namespaces on its node.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/agent"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/ebpf"
	"github.com/skaldhall/ratatoskr/pkg/observability"
	"github.com/skaldhall/ratatoskr/pkg/platform"
	"github.com/skaldhall/ratatoskr/pkg/version"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Agent metrics bind its Pod IP by default; a scrape ingress policy must
// restrict sources independently of the health/readiness listener.
const agentMetricsAddr = "0.0.0.0:9903"

// Health uses the chart-selected port inside the agent Pod's network namespace.
func agentHealthAddress() (string, error) {
	port := os.Getenv("HEALTH_PORT")
	if port == "" {
		port = "19903"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("HEALTH_PORT must be an integer from 1 to 65535")
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(n)), nil
}

func agentMetricsServer(programming *observability.AgentProgramming) (*http.Server, net.Listener, error) {
	address, err := observability.MetricsBindAddress(os.Getenv("METRICS_BIND_ADDRESS"), agentMetricsAddr)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", observability.AgentHandler(programming))
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	listener, err := net.Listen("tcp4", server.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen agent metrics: %w", err)
	}
	return server, listener, nil
}

func run(ctx context.Context) error {
	if err := platform.CheckKernel(); err != nil {
		return err
	}
	node, socket := os.Getenv("NODE_NAME"), os.Getenv("CRI_SOCKET")
	own := agent.OwnPod{Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("POD_NAME"), UID: os.Getenv("POD_UID"), Node: node}
	if node == "" || socket == "" || own.Namespace == "" || own.Name == "" || own.UID == "" {
		return errors.New("NODE_NAME and CRI_SOCKET are required")
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	if err := api.AddToScheme(scheme); err != nil {
		return err
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	k, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connect CRI: %w", err)
	}
	defer conn.Close()
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := cri.NewRuntimeServiceClient(conn).Version(dialCtx, &cri.VersionRequest{Version: "0.1.0"}); err != nil {
		return fmt.Errorf("CRI handshake: %w", err)
	}
	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ready := &atomic.Bool{}
	programming := observability.NewAgentProgramming()
	reconciler := &agent.Reconciler{Ready: ready, Client: k, WatchClient: k, CRI: cri.NewRuntimeServiceClient(conn), Tokens: &agent.KubernetesTokenIssuer{Client: k8s}, Node: node, OperatorNamespace: os.Getenv("OPERATOR_NAMESPACE"), Datapath: os.Getenv("DATAPATH"), EBPFBackend: func() (datapath.Backend, error) { return ebpf.New() }, Log: logger, Own: own, Programming: programming}
	if err := reconciler.Bootstrap(ctx); err != nil {
		return fmt.Errorf("verify isolated agent namespace bootstrap: %w", err)
	}
	metricsEnabled, err := observability.MetricsEnabled(os.Getenv("METRICS_ENABLED"))
	if err != nil {
		return err
	}
	if metricsEnabled {
		metrics, metricsListener, err := agentMetricsServer(programming)
		if err != nil {
			return err
		}
		go func() {
			if err := metrics.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("agent metrics server failed", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := metrics.Shutdown(shutdownCtx); err != nil {
				logger.Error("agent metrics shutdown failed", "error", err)
			}
		}()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"status":"not-ready"}`)
			return
		}
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	healthAddress, err := agentHealthAddress()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", healthAddress) // #nosec G102 -- node health probes require a pod-network reachable bind.
	if err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server failed", "error", err)
		}
	}()
	defer func() {
		if err := server.Shutdown(context.Background()); err != nil {
			logger.Error("health shutdown failed", "error", err)
		}
	}()
	return reconciler.Run(ctx)
}
func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-agent", version.String())
		return
	}
	if err := run(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintln(os.Stderr, "ratatoskr-agent:", err)
		os.Exit(1)
	}
}
