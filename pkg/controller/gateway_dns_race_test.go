package controller

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type staleDNSCache struct {
	client.Client
	reads int
}

func (c *staleDNSCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Service); ok && key.Name == "edge-dns" {
		c.reads++
		return apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, key.Name)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

type dnsAPIReader struct {
	client.Reader
	kind  string
	reads int
}

func (a *dnsAPIReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Service); ok && key.Name == "edge-dns" {
		a.reads++
		switch a.kind {
		case "notfound":
			return apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, key.Name)
		case "forbidden":
			return apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, key.Name, errors.New("SECRET-TOKEN-URL"))
		}
	}
	return a.Reader.Get(ctx, key, obj, opts...)
}
func setupGatewayDNSRace(t *testing.T) (*GatewayReconciler, *api.EgressGateway, ctrl.Request) {
	t.Helper()
	r, gw := fixture(t)
	ctx := context.Background()
	gw.Spec.DNS.Mode = "gateway"
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{}
	if err := r.Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.1"}}, {ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.10"}}} {
		if err := r.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	} // allocate Gateway ID
	return r, gw, req
}
func TestGatewayDNSPostApplyUncachedReaderBypassesStaleCache(t *testing.T) {
	r, _, req := setupGatewayDNSRace(t)
	underlying := r.Client
	cache := &staleDNSCache{Client: underlying}
	r.Client = cache
	reader := &dnsAPIReader{Reader: underlying}
	r.APIReader = reader
	if result, err := r.Reconcile(context.Background(), req); err != nil || result.RequeueAfter <= 0 {
		t.Fatalf("uncached DNS Service GET blocked: %v %+v", err, result)
	}
	if cache.reads != 1 || reader.reads != 1 {
		t.Fatalf("postapply must use uncached APIReader: cached reads=%d direct=%d", cache.reads, reader.reads)
	}
	var dep appsv1.Deployment
	if err := underlying.Get(context.Background(), req.NamespacedName, &dep); err != nil {
		t.Fatalf("Gateway Deployment was deleted: %v", err)
	}
	var svc corev1.Service
	if err := underlying.Get(context.Background(), types.NamespacedName{Namespace: req.Namespace, Name: "edge-dns"}, &svc); err != nil || !metav1.IsControlledBy(&svc, &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{UID: types.UID("unique-gateway")}}) {
		t.Fatalf("owned DNS Service unavailable: %v", err)
	}
}
func TestGatewayDNSPostApplyNotFoundRequeuesWithoutDeletingDeployment(t *testing.T) {
	r, _, req := setupGatewayDNSRace(t)
	reader := &dnsAPIReader{Reader: r.Client, kind: "notfound"}
	r.APIReader = reader
	result, err := r.Reconcile(context.Background(), req)
	if err != nil || result.RequeueAfter <= 0 || reader.reads != 1 {
		t.Fatalf("freshly created DNS Service cache miss was not retried: %v %+v", err, result)
	}
	if err := r.Get(context.Background(), req.NamespacedName, &appsv1.Deployment{}); err != nil {
		t.Fatalf("transient DNS read removed Gateway Deployment: %v", err)
	}
	gw := getGatewayForFailureEvent(t, r, req.Name)
	if ready := meta.FindStatusCondition(gw.Status.Conditions, "Ready"); ready != nil && ready.Status == metav1.ConditionTrue {
		t.Fatal("transient DNS read published new Ready status")
	}
}
func TestGatewayDNSFailureAdviceNoSecretInStatusEventOrLogs(t *testing.T) {
	r, gw, req := setupGatewayDNSRace(t)
	recorder := events.NewFakeRecorder(5)
	r.Recorder = recorder
	var output bytes.Buffer
	ctx := log.IntoContext(context.Background(), logr.New(&safeLogSink{output: &output}))
	reader := &dnsAPIReader{Reader: r.Client, kind: "forbidden"}
	r.APIReader = reader
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	stored := getGatewayForFailureEvent(t, r, gw.Name)
	ready := meta.FindStatusCondition(stored.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "DNSUnavailable" || !strings.Contains(ready.Message, "services get") || strings.Contains(ready.Message, "SECRET-TOKEN-URL") {
		t.Fatalf("unsafe DNS condition: %+v", ready)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "services get") || strings.Contains(event, "SECRET-TOKEN-URL") {
			t.Fatalf("unsafe DNS Event: %q", event)
		}
	default:
		t.Fatal("missing DNS failure Event")
	}
	if strings.Contains(output.String(), "SECRET-TOKEN-URL") || !strings.Contains(output.String(), "GatewayServiceReadDenied") {
		t.Fatal("unsafe DNS failure log")
	}
	if err := r.Get(ctx, req.NamespacedName, &appsv1.Deployment{}); err == nil {
		t.Fatal("permanent forbidden DNS read did not fail closed")
	}
}
func TestGatewayDNSOwnedServiceWithInvalidIPv4Closes(t *testing.T) {
	r, gw, req := setupGatewayDNSRace(t)
	ctx := context.Background()
	r.Options.GatewayUpstreamDNSIP = "9.9.9.9"
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var svc corev1.Service
	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name + "-dns"}
	if err := r.Get(ctx, key, &svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.ClusterIP = "not-an-ip"
	if err := r.Update(ctx, &svc); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	stored := getGatewayForFailureEvent(t, r, gw.Name)
	ready := meta.FindStatusCondition(stored.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionFalse || !strings.Contains(ready.Message, "ClusterIP") {
		t.Fatalf("invalid Gateway DNS IPv4 did not fail closed: %+v", ready)
	}
	if err := r.Get(ctx, req.NamespacedName, &appsv1.Deployment{}); err == nil {
		t.Fatal("invalid Gateway DNS Service left forwarding Deployment")
	}
}

func TestGatewayDNSAdviceFixedCategories(t *testing.T) {
	for _, tc := range []struct{ code, want string }{
		{"ClusterDNSIPv4Missing", "dns.clusterIP"},
		{"GatewayServiceIPv4Missing", "ClusterIP"},
		{"GatewayServiceReadDenied", "services get"},
		{"GatewayServiceReadFailed", "API availability"},
		{"GatewayServiceOwnership", "another owner"},
	} {
		code, text := dnsAdvice(&dnsFailure{code: tc.code, cause: errors.New("SECRET-TOKEN-URL")})
		if code != tc.code || !strings.Contains(text, tc.want) || strings.Contains(text, "SECRET-TOKEN-URL") {
			t.Fatalf("unsafe DNS category %s %s", code, text)
		}
	}
	code, text := dnsAdvice(errors.New("SECRET-TOKEN-URL"))
	if code != "Unknown" || strings.Contains(text, "SECRET-TOKEN-URL") {
		t.Fatal("unknown DNS error leaked")
	}
}
