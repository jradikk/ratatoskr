package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInitAckRequiresAppliedEndpointAndExactClient(t *testing.T) {
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "operator", UID: types.UID("gw-uid"), Generation: 2}, Status: api.EgressGatewayStatus{GatewayID: 11, ObservedGeneration: 2}}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "apps", UID: types.UID("workload-uid"), Annotations: map[string]string{}}, Status: corev1.PodStatus{PodIP: "10.1.0.2"}}
	client := datapath.ClientConfig{GatewayID: 11, Endpoint: netip.MustParseAddr("10.2.0.3"), Identity: datapath.Identity{Namespace: "apps", Pod: "client"}}
	encoded, _ := json.Marshal(client)
	p.Annotations["ratatoskr.skaldhall.io/client-config"] = string(encoded)
	config := datapath.GatewayConfig{GatewayID: 11, MTU: 1400, Encryption: "none", Clients: []netip.Addr{netip.MustParseAddr(p.Status.PodIP)}}
	rawBytes, _ := json.Marshal(config)
	raw := string(rawBytes)
	sum := sha256.Sum256(rawBytes)
	ep := api.GatewayEndpoint{PodName: "endpoint", PodIP: "10.2.0.3", PodUID: "gateway-pod-uid", UpstreamHealthy: true, AppliedClientConfigHash: hex.EncodeToString(sum[:])}
	gw.Status.Endpoints = []api.GatewayEndpoint{ep}
	if appliedInitAck(gw, p, raw) == "" {
		t.Fatal("valid applied client not acknowledged")
	}
	gw.Status.Endpoints[0].AppliedClientConfigHash = ""
	if appliedInitAck(gw, p, raw) != "" {
		t.Fatal("missing applied hash acknowledged")
	}
	gw.Status.Endpoints[0] = ep
	config.Clients = nil
	wrong, _ := json.Marshal(config)
	if appliedInitAck(gw, p, string(wrong)) != "" {
		t.Fatal("unselected client acknowledged")
	}
	gw.Status.ObservedGeneration = 1
	if appliedInitAck(gw, p, raw) != "" {
		t.Fatal("stale generation acknowledged")
	}
	gw.Status.ObservedGeneration = 2
	gw.Status.Endpoints[0].PodUID = ""
	if appliedInitAck(gw, p, raw) != "" {
		t.Fatal("missing endpoint UID acknowledged")
	}
}

func TestControllerProjectsAndWithdrawsInitAck(t *testing.T) {
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "operator", UID: types.UID("gateway-uid"), Generation: 1}, Spec: api.EgressGatewaySpec{AllowedNamespaces: api.AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{}}}, Status: api.EgressGatewayStatus{GatewayID: 11, ObservedGeneration: 1}}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "apps", UID: types.UID("client-uid"), Labels: map[string]string{GatewayLabel: gw.Name}, Annotations: map[string]string{initAppliedAckAnnotation: ""}}, Status: corev1.PodStatus{PodIP: "10.1.0.2"}}
	config := datapath.ClientConfig{GatewayID: 11, Endpoint: netip.MustParseAddr("10.2.0.3"), Identity: datapath.Identity{Namespace: p.Namespace, Pod: p.Name}}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	p.Annotations["ratatoskr.skaldhall.io/client-config"] = string(b)
	gatewayConfig := datapath.GatewayConfig{GatewayID: 11, MTU: 1400, Encryption: "none", Clients: []netip.Addr{netip.MustParseAddr(p.Status.PodIP)}}
	raw, err := json.Marshal(gatewayConfig)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	gw.Status.Endpoints = []api.GatewayEndpoint{{PodName: "gateway-pod", PodIP: config.Endpoint.String(), PodUID: "gateway-pod-uid", AppliedClientConfigHash: hex.EncodeToString(hash[:]), UpstreamHealthy: true}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: p.Namespace}}
	scheme := runtime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err = api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, p).Build()
	r := &GatewayReconciler{Client: k, Options: Options{OperatorNamespace: "operator", Driver: "init"}}
	ctx := context.Background()
	if err = r.reconcileInitAppliedAck(ctx, gw, string(raw)); err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		var got corev1.Pod
		if err := k.Get(ctx, client.ObjectKeyFromObject(p), &got); err != nil {
			t.Fatal(err)
		}
		if (got.Annotations[initAppliedAckAnnotation] != "") != want {
			t.Fatalf("projected ack=%q; want present=%v", got.Annotations[initAppliedAckAnnotation], want)
		}
	}
	check(true)
	gw.Status.Endpoints[0].AppliedClientConfigHash = ""
	if err = r.reconcileInitAppliedAck(ctx, gw, string(raw)); err != nil {
		t.Fatal(err)
	}
	check(false)
	gw.Status.Endpoints[0].AppliedClientConfigHash = hex.EncodeToString(hash[:])
	gw.Spec.AllowedNamespaces.NamespaceSelector = nil
	if err = r.reconcileInitAppliedAck(ctx, gw, string(raw)); err != nil {
		t.Fatal(err)
	}
	check(false)
}
