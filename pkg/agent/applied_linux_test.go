//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ackFixtures(t *testing.T) (*api.EgressGateway, datapath.ClientConfig, string, string, *corev1.ConfigMap, *corev1.Pod) {
	t.Helper()
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "operator", UID: types.UID("gw-uid"), Generation: 7}, Status: api.EgressGatewayStatus{ObservedGeneration: 7, GatewayID: 11, Endpoints: []api.GatewayEndpoint{{PodName: "vpn-pod", PodIP: "10.2.0.3", UpstreamHealthy: true, PodUID: "pod-uid"}}}}
	cfg := datapath.ClientConfig{GatewayID: 11, PodIP: netip.MustParseAddr("10.1.0.2"), Endpoint: netip.MustParseAddr("10.2.0.3"), MTU: 1400, Encryption: "none"}
	desired := datapath.GatewayConfig{GatewayID: 11, MTU: 1400, Encryption: "none", Clients: []netip.Addr{cfg.PodIP}}
	rawBytes, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	sum := sha256.Sum256(rawBytes)
	hash := hex.EncodeToString(sum[:])
	gw.Status.Endpoints[0].AppliedClientConfigHash = hash
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}}, Data: map[string]string{"gateway.json": raw}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "vpn-pod", Namespace: gw.Namespace, UID: types.UID("pod-uid")}, Status: corev1.PodStatus{PodIP: cfg.Endpoint.String()}}
	return gw, cfg, raw, hash, cm, pod
}
func TestExactRawAppliedConfig(t *testing.T) {
	_, cfg, raw, hash, _, _ := ackFixtures(t)
	if err := checkAppliedRaw(raw, hash, cfg, cfg.Endpoint); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, raw, hash string
		config          datapath.ClientConfig
	}{
		{"stale ConfigMap", raw + " ", hash, cfg},
		{"missing ack", raw, "", cfg},
		{"client omitted", strings.Replace(raw, `"10.1.0.2"`, `"10.1.0.9"`, 1), hash, cfg},
		{"wrong gateway ID", raw, hash, func() datapath.ClientConfig { v := cfg; v.GatewayID = 12; return v }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkAppliedRaw(tc.raw, tc.hash, tc.config, tc.config.Endpoint); err == nil {
				t.Fatal("unacknowledged config accepted")
			}
		})
	}
}
func TestAppliedGatewayStatusAndOwner(t *testing.T) {
	gw, cfg, _, hash, cm, pod := ackFixtures(t)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	check := func(g *api.EgressGateway, c *corev1.ConfigMap, p *corev1.Pod) error {
		k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(c, p).Build()
		r := &Reconciler{Client: k}
		uid, h, e := selectedAck(g, cfg)
		if e != nil {
			return e
		}
		return r.appliedGateway(context.Background(), g, cfg, uid, h)
	}
	if err := check(gw, cm, pod); err != nil {
		t.Fatal(err)
	}
	gw.Status.Endpoints[0].AppliedClientConfigHash = ""
	if err := check(gw, cm, pod); err == nil {
		t.Fatal("empty applied ack accepted")
	}
	gw.Status.Endpoints[0].AppliedClientConfigHash = hash
	pod.UID = "replaced"
	if err := check(gw, cm, pod); err == nil {
		t.Fatal("replaced endpoint Pod UID accepted")
	}
	pod.UID = "pod-uid"
	cm.OwnerReferences = nil
	if err := check(gw, cm, pod); err == nil {
		t.Fatal("unowned ConfigMap accepted")
	}
	cm.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}
	gw.Status.Endpoints = append(gw.Status.Endpoints, gw.Status.Endpoints[0])
	if err := check(gw, cm, pod); err == nil {
		t.Fatal("ambiguous endpoint accepted")
	}
}
