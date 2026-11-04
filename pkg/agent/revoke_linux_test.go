//go:build linux

package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/datapath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type revokeClient struct {
	client.Client
	fail string
}

func (c *revokeClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	switch obj.(type) {
	case *corev1.Namespace:
		if c.fail == "namespace" {
			return errors.New("namespace read failed")
		}
	case *corev1.Pod:
		if c.fail == "ownpod" {
			return errors.New("own agent Pod read failed")
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}
func (c *revokeClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.fail == "policy" {
		return errors.New("policy list failed")
	}
	return c.Client.List(ctx, list, opts...)
}
func TestRevocationNeverTrustsStoredAgentHash(t *testing.T) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "ns", UID: types.UID("uid"), Labels: map[string]string{GatewayLabel: "gone"}, Annotations: map[string]string{HashAnnotation: "attacker-hash", ConfigAnnotation: `{"gatewayID":16777215,"podIP":"10.0.0.4"}`, ReadyAnnotation: "true"}}, Spec: corev1.PodSpec{NodeName: "node"}, Status: corev1.PodStatus{PodIP: "10.0.0.4"}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(p).Build()
	for _, tc := range []struct {
		name   string
		mutate func(*revokeClient)
	}{
		{"namespace read error", func(c *revokeClient) { c.fail = "namespace" }},
		{"gateway deleted", func(c *revokeClient) { c.fail = "" }},
		{"policy read error", func(c *revokeClient) { c.fail = "policy" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &revokeClient{Client: base}
			tc.mutate(c)
			r := &Reconciler{Client: c, Node: "node", OperatorNamespace: "operator", Log: slog.Default()}
			// The revocation seam returns the ORIGINAL error when CRI is unavailable;
			// it must never program routes from forged annotations or mark ready.
			if err := r.Reconcile(context.Background(), p.DeepCopy()); err == nil {
				t.Fatal("authorization failure accepted without verified quarantine")
			}
			var current corev1.Pod
			if err := base.Get(context.Background(), types.NamespacedName{Namespace: p.Namespace, Name: p.Name}, &current); err != nil {
				t.Fatal(err)
			}
			if current.Annotations[ReadyAnnotation] != "true" {
				t.Fatal("mutated API before verified sandbox quarantine")
			}
		})
	}
}

// This seam is executable without namespace privileges: it proves a forged
// persisted gateway/table cannot be passed to ApplyClient when the CRI sandbox
// cannot be independently verified. The live netns guard is in privileged tests.
func TestRevokeSelectedForgedConfigNeverCallsBackend(t *testing.T) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "ns", UID: types.UID("uid"), Annotations: map[string]string{HashAnnotation: "forged", ConfigAnnotation: `{"gatewayID":16777215,"podIP":"10.0.0.4"}`, ReadyAnnotation: "true"}}, Spec: corev1.PodSpec{NodeName: "node"}, Status: corev1.PodStatus{PodIP: "10.0.0.4"}}
	called := false
	r := &Reconciler{Node: "node", EBPFBackend: func() (datapath.Backend, error) { called = true; return nil, errors.New("backend called") }}
	if err := r.revokeSelected(context.Background(), p, quarantineGatewayRead); err == nil {
		t.Fatal("unverified sandbox revocation accepted")
	}
	if called {
		t.Fatal("forged stored config reached a backend")
	}
}
