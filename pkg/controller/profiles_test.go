package controller

import (
	"context"
	"net/netip"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func gatewayWithProfiles(t *testing.T) (*GatewayReconciler, *api.EgressGateway) {
	t.Helper()
	r, gw := fixture(t)
	gw.Spec.Upstream.SecretRef = api.SecretReference{}
	gw.Spec.Replicas = 1
	gw.Spec.Upstream.Profiles = []api.UpstreamProfile{{Name: "berlin", SecretRef: api.SecretReference{Name: "berlin-key"}}, {Name: "oslo", SecretRef: api.SecretReference{Name: "oslo-key"}}}
	gw.Status.GatewayID = 17
	return r, gw
}
func TestGatewayProfileRenderedIsolationAndLegacy(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	objects, err := r.render(gw, []netip.Addr{netip.MustParseAddr("10.2.0.8")})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, obj := range objects {
		d, ok := obj.(*appsv1.Deployment)
		if !ok {
			continue
		}
		names = append(names, d.Name)
		if d.Labels[IdentityLabel] != gw.Name || d.Labels[ownerUIDLabel] != string(gw.UID) || d.Labels[profileLabel] == "" || *d.Spec.Replicas != 1 {
			t.Fatal("profile deployment identity/replicas invalid")
		}
		if d.Spec.Template.Spec.Volumes[1].Secret.SecretName != d.Labels[profileLabel]+"-key" {
			t.Fatal("profile leaked wrong Secret")
		}
		if d.Spec.Template.Spec.Volumes[0].ConfigMap.Name != gw.Name {
			t.Fatal("gateway config not shared")
		}
		if len(d.Spec.Template.Spec.Volumes[1].Secret.Items) != 0 {
			t.Fatal("profile Secret values must not be serialized into Pod template")
		}
	}
	if len(names) != 2 || names[0] != "edge-berlin" || names[1] != "edge-oslo" {
		t.Fatalf("profile Deployments %v", names)
	}
	cm := objects[0].(*corev1.ConfigMap)
	if len(cm.Data) != 1 || cm.Data["gateway.json"] == "" {
		t.Fatal("shared config missing")
	}
	svc := objects[1].(*corev1.Service)
	if svc.Spec.Selector[IdentityLabel] != gw.Name || svc.Spec.Selector[ownerUIDLabel] != string(gw.UID) {
		t.Fatal("common gateway selector broken")
	}
	gw.Spec.Upstream.Profiles = nil
	gw.Spec.Upstream.SecretRef = api.SecretReference{Name: "vpn"}
	legacy, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 4 || legacy[2].(*appsv1.Deployment).Name != gw.Name {
		t.Fatal("legacy gateway changed")
	}
}
func TestGatewayProfileNamesRejectAmbiguity(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	_ = r
	for _, mutate := range []func(*api.EgressGateway){
		func(g *api.EgressGateway) { g.Spec.Upstream.SecretRef.Name = "vpn" },
		func(g *api.EgressGateway) { g.Spec.Replicas = 2 },
		func(g *api.EgressGateway) { g.Spec.Upstream.Profiles[1].Name = "berlin" },
		func(g *api.EgressGateway) { g.Spec.Upstream.Profiles[1].SecretRef.Name = "" },
		func(g *api.EgressGateway) { g.Name = "gateway-name-that-exceeds-fifty-chars-long-enough-for-profile" },
	} {
		bad := gw.DeepCopy()
		mutate(bad)
		if _, err := gatewayProfileNames(bad); err == nil {
			t.Fatal("ambiguous profile accepted")
		}
	}
}
func TestGatewayProfilePodOwnerAndRemovedDeployment(t *testing.T) {
	r, gw := gatewayWithProfiles(t)
	ctx := context.Background()
	desired, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range desired {
		if dep, ok := obj.(*appsv1.Deployment); ok {
			dep.UID = types.UID(dep.Name + "-uid")
			if err := r.Create(ctx, dep); err != nil {
				t.Fatal(err)
			}
		}
	}
	dep := desired[2].(*appsv1.Deployment)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "edge-berlin-rs", Namespace: gw.Namespace, UID: "rs-berlin", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	if err := r.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "edge-berlin-pod", Namespace: gw.Namespace, Labels: map[string]string{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID), profileLabel: "berlin"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}}
	if managed, err := r.managedGatewayPod(ctx, gw, pod); err != nil || !managed {
		t.Fatalf("profile Pod rejected: %v %v", managed, err)
	}
	changed := pod.DeepCopy()
	changed.OwnerReferences[0].UID = "wrong"
	if managed, _ := r.managedGatewayPod(ctx, gw, changed); managed {
		t.Fatal("forged ReplicaSet accepted")
	}
	bad := gw.DeepCopy()
	bad.Spec.Upstream.Profiles = bad.Spec.Upstream.Profiles[1:]
	if managed, _ := r.managedGatewayPod(ctx, bad, pod); managed {
		t.Fatal("removed profile Pod accepted")
	}
	remaining, err := r.render(bad, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.removeStaleProfileDeployments(ctx, bad, remaining); err != nil {
		t.Fatal(err)
	}
	var removed appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), &removed); err == nil {
		t.Fatal("removed profile still serves")
	}
	var kept appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(desired[3]), &kept); err != nil {
		t.Fatal("retained profile deleted")
	}
}
