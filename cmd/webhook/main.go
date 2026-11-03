// Command webhook mutates opted-in pods and validates Ratatoskr objects.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	server "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/observability"
	"github.com/skaldhall/ratatoskr/pkg/version"
	ratatoskr "github.com/skaldhall/ratatoskr/pkg/webhook"
)

func run(ctx context.Context, bootstrap bool, dir string) error {
	metricsAddress, err := observability.ManagerMetricsBindAddress(os.Getenv("METRICS_ENABLED"), os.Getenv("METRICS_BIND_ADDRESS"), "0.0.0.0:9904")
	if err != nil {
		return err
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load Kubernetes config: %w", err)
	}
	if bootstrap {
		client, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		return ratatoskr.BootstrapTLS(ctx, client, os.Getenv("NAMESPACE"), os.Getenv("SERVICE_NAME"), os.Getenv("CLUSTER_DOMAIN"), os.Getenv("TLS_SECRET_NAME"), os.Getenv("MUTATING_WEBHOOK_NAME"), os.Getenv("VALIDATING_WEBHOOK_NAME"), dir)
	}
	if os.Getenv("NAMESPACE") == "" || os.Getenv("INIT_IMAGE") == "" {
		return fmt.Errorf("NAMESPACE and INIT_IMAGE must be set")
	}
	scheme := runtime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		return err
	}
	if err = v1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, HealthProbeBindAddress: ":8081", Metrics: metricsserver.Options{BindAddress: metricsAddress}, WebhookServer: server.NewServer(server.Options{Port: 9443, CertDir: dir, CertName: "tls.crt", KeyName: "tls.key"}), Client: crclient.Options{Cache: &crclient.CacheOptions{DisableFor: []crclient.Object{&corev1.Namespace{}, &corev1.Service{}, &corev1.Pod{}}}}})
	if err != nil {
		return fmt.Errorf("configure webhook manager: %w", err)
	}
	h := &ratatoskr.Handler{Client: mgr.GetClient(), Namespace: operatorNamespace(), AgentNamespace: os.Getenv("NAMESPACE"), InitImage: os.Getenv("INIT_IMAGE"), ClusterDomain: os.Getenv("CLUSTER_DOMAIN"), Driver: os.Getenv("DRIVER"), Datapath: os.Getenv("DATAPATH")}
	mgr.GetWebhookServer().Register("/mutate-v1alpha1-pod", &admission.Webhook{Handler: admission.HandlerFunc(h.MutatePod)})
	mgr.GetWebhookServer().Register("/validate-v1alpha1", &admission.Webhook{Handler: admission.HandlerFunc(h.Validate)})
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err = mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
		return err
	}
	return mgr.Start(ctx)
}

// The webhook serves TLS in NAMESPACE, which may differ from the operator's
// default gateway namespace. Keep the historical fallback for local installs.
func operatorNamespace() string {
	if namespace := os.Getenv("OPERATOR_NAMESPACE"); namespace != "" {
		return namespace
	}
	return os.Getenv("NAMESPACE")
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	bootstrap := flag.Bool("bootstrap-tls", false, "bootstrap webhook TLS Secret and CA bundles")
	tlsDir := flag.String("tls-dir", "/tls", "shared TLS directory")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-webhook", version.String())
		return
	}
	ctrl.SetLogger(logr.FromSlogHandler(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(ctrl.SetupSignalHandler(), *bootstrap, *tlsDir); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("webhook failed", "error", err)
		os.Exit(1)
	}
}
