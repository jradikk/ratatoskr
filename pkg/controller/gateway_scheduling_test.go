package controller

import (
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestGatewayPodsPreferDifferentNodesAcrossReplicasAndProfiles(t *testing.T) {
	for _, profiles := range []bool{false, true} {
		r, gw := fixture(t)
		gw.Spec.NodeSelector = map[string]string{"pool": "vpn"}
		if profiles {
			gw.Spec.Upstream.SecretRef = api.SecretReference{}
			gw.Spec.Upstream.Profiles = []api.UpstreamProfile{{Name: "a", SecretRef: api.SecretReference{Name: "a-vpn"}}, {Name: "b", SecretRef: api.SecretReference{Name: "b-vpn"}}}
		} else {
			gw.Spec.Replicas = 2
		}
		objects, err := r.render(gw, nil)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, obj := range objects {
			dep, ok := obj.(*appsv1.Deployment)
			if !ok {
				continue
			}
			count++
			pod := dep.Spec.Template.Spec
			if pod.Affinity == nil || pod.Affinity.PodAntiAffinity == nil {
				t.Fatal("gateway anti-affinity missing")
			}
			aa := pod.Affinity.PodAntiAffinity
			if len(aa.RequiredDuringSchedulingIgnoredDuringExecution) != 0 || len(aa.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
				t.Fatal("gateway spreading must be a soft preference")
			}
			term := aa.PreferredDuringSchedulingIgnoredDuringExecution[0]
			if term.Weight != 100 || term.PodAffinityTerm.TopologyKey != "kubernetes.io/hostname" {
				t.Fatal("unexpected spreading weight or topology")
			}
			selector, err := metav1.LabelSelectorAsSelector(term.PodAffinityTerm.LabelSelector)
			if err != nil {
				t.Fatal(err)
			}
			for _, profile := range []string{"a", "b"} {
				if !selector.Matches(labels.Set{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID), profileLabel: profile}) {
					t.Fatal("selector must span all gateway profiles")
				}
			}
			if selector.Matches(labels.Set{IdentityLabel: "other", ownerUIDLabel: "other-uid"}) {
				t.Fatal("spreading must not include unrelated gateways")
			}
			if pod.NodeSelector["pool"] != "vpn" {
				t.Fatal("gateway node selector lost")
			}
		}
		if (!profiles && count != 1) || (profiles && count != 2) {
			t.Fatalf("unexpected deployment count: %d", count)
		}
	}
}
