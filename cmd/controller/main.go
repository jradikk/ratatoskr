// Command controller manages namespaced EgressGateway workloads.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-logr/logr"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/controller"
	"github.com/skaldhall/ratatoskr/pkg/version"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	leader := flag.Bool("leader-elect", false, "enable leader election")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-controller", version.String())
		return
	}
	ctrl.SetLogger(logr.FromSlogHandler(slog.NewJSONHandler(os.Stderr, nil)))
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(api.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme, HealthProbeBindAddress: ":8081", Metrics: server.Options{BindAddress: "0"}, LeaderElection: *leader, LeaderElectionID: "ratatoskr-controller.skaldhall.io"})
	if err == nil {
		r := &controller.GatewayReconciler{Client: mgr.GetClient(), Scheme: scheme, Recorder: mgr.GetEventRecorder("egressgateway-controller"), Options: controller.OptionsFromEnv()}
		err = r.SetupWithManager(mgr)
	}
	if err == nil {
		err = mgr.AddHealthzCheck("healthz", healthz.Ping)
	}
	if err == nil {
		err = mgr.AddReadyzCheck("readyz", healthz.Ping)
	}
	if err == nil {
		err = mgr.Start(ctrl.SetupSignalHandler())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "controller failed:", err)
		os.Exit(1)
	}
}
