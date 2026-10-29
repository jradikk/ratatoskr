package controller

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }
func TestGatewayMTURequiresMeasuredSafeLinks(t *testing.T) {
	for _, tt := range []struct {
		name, payload string
		ready         bool
		reason        string
		mtu           int32
	}{
		{"safe", `{"exitIP":"198.51.100.9","ready":true,"podMTU":1500,"geneveMTU":1450,"upstreamMTU":1400,"effectiveMTU":1400,"mss":1360}`, true, "", 1400},
		{"unsafe", `{"exitIP":"198.51.100.9","ready":true,"podMTU":1300,"geneveMTU":1200,"upstreamMTU":1100,"effectiveMTU":1100,"mss":1060}`, true, "MTUWarning", 1100},
		{"unknown", `{"exitIP":"198.51.100.9","ready":true}`, false, "MTUUnknown", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, gw := fixture(t)
			gw.Status.GatewayID = 42
			ctx := context.Background()
			if err := r.Status().Update(ctx, gw); err != nil {
				t.Fatal(err)
			}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway-1", Namespace: "operator", Labels: map[string]string{ownerUIDLabel: string(gw.UID)}}, Status: corev1.PodStatus{PodIP: "10.42.0.5", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
			if err := r.Create(ctx, pod); err != nil {
				t.Fatal(err)
			}
			if err := r.Status().Update(ctx, pod); err != nil {
				t.Fatal(err)
			}
			r.HTTPClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tt.payload)), Header: http.Header{}}, nil
			})}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: gw.Name, Namespace: gw.Namespace}}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatal(err)
			}
			if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
				t.Fatal(err)
			}
			if meta.IsStatusConditionTrue(gw.Status.Conditions, "Ready") != tt.ready || gw.Status.MTU.EffectiveMTU != tt.mtu {
				t.Fatalf("incorrect measured MTU status: %+v", gw.Status)
			}
			if tt.reason != "" && !meta.IsStatusConditionTrue(gw.Status.Conditions, tt.reason) {
				t.Fatalf("missing %s condition: %+v", tt.reason, gw.Status.Conditions)
			}
			if len(gw.Status.Endpoints) != 1 || gw.Status.Endpoints[0].UpstreamHealthy != tt.ready {
				t.Fatalf("unsafe endpoint exposed: %+v", gw.Status.Endpoints)
			}
		})
	}
}
