package controller

import (
	"context"
	"net/netip"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func containsExclusion(items []api.EffectiveExclusion, cidr, source string) bool {
	for _, item := range items {
		if item.CIDR == cidr && item.Source == source {
			return true
		}
	}
	return false
}
func TestExclusionDiscoveryFromClusterAPIs(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	r.Options.ServiceCIDRs = ""
	r.Options.PodCIDRs = ""
	r.Options.ClusterDNSIP = "10.90.0.10"
	r.Options.ExtraCIDRs = "192.0.2.0/24"
	gw.Spec.Exclusions.ExtraCIDRs = []string{"198.51.100.0/24"}
	objects := []interface{}{
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{PodCIDRs: []string{"10.20.0.0/24", "fd00::/64"}}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "172.16.1.2"}}}},
		&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.90.0.0/16", "fd01::/108"}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.90.0.1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.90.0.10"}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "default", Labels: map[string]string{discoveryv1.LabelServiceName: "kubernetes"}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"172.16.1.10"}}}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "dns-1", Namespace: "kube-system", Labels: map[string]string{discoveryv1.LabelServiceName: "kube-dns"}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.20.0.53"}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway-pod", Namespace: "operator", Labels: map[string]string{ownerUIDLabel: string(gw.UID)}}, Status: corev1.PodStatus{PodIP: "10.20.0.5"}},
	}
	for _, obj := range objects {
		switch o := obj.(type) {
		case *corev1.Node:
			if err := r.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		case *networkingv1.ServiceCIDR:
			if err := r.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		case *corev1.Service:
			if err := r.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		case *discoveryv1.EndpointSlice:
			if err := r.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		case *corev1.Pod:
			if err := r.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
			if err := r.Status().Update(ctx, o); err != nil {
				t.Fatal(err)
			}
		}
	}
	exclusions, dns, err := r.collectExclusions(ctx, gw)
	if err != nil {
		t.Fatal(err)
	}
	if dns != "10.90.0.10" {
		t.Fatalf("DNS address %q", dns)
	}
	for _, want := range []api.EffectiveExclusion{{CIDR: "10.20.0.0/24", Source: "podCIDR"}, {CIDR: "10.90.0.0/16", Source: "serviceCIDR"}, {CIDR: "172.16.1.2/32", Source: "node"}, {CIDR: "172.16.1.10/32", Source: "apiserver"}, {CIDR: "10.90.0.1/32", Source: "apiserver"}, {CIDR: "10.90.0.10/32", Source: "dns"}, {CIDR: "10.20.0.53/32", Source: "dns"}, {CIDR: "169.254.0.0/16", Source: "linkLocal"}, {CIDR: "192.0.2.0/24", Source: "extra"}, {CIDR: "198.51.100.0/24", Source: "extra"}, {CIDR: "10.20.0.5/32", Source: "extra"}} {
		if !containsExclusion(exclusions, want.CIDR, want.Source) {
			t.Errorf("missing exclusion %s from %s: %+v", want.CIDR, want.Source, exclusions)
		}
	}
}
func TestServiceCIDRFallbackAndUnknownFailure(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	result, _, err := r.collectExclusions(ctx, gw)
	if err != nil || !containsExclusion(result, "10.43.0.0/16", "serviceCIDR") {
		t.Fatalf("configured fallback unavailable: %v %+v", err, result)
	}
	r.Options.ServiceCIDRs = ""
	if _, _, err := r.collectExclusions(ctx, gw); err == nil {
		t.Fatal("unknown ServiceCIDR accepted")
	}
	r.Options.ServiceCIDRs = "not-a-cidr"
	if _, _, err := r.collectExclusions(ctx, gw); err == nil {
		t.Fatal("invalid configured ServiceCIDR accepted")
	}
	r.Options.ServiceCIDRs = "10.43.0.0/16"
	r.Options.PodCIDRs = ""
	if _, _, err := r.collectExclusions(ctx, gw); err == nil {
		t.Fatal("unknown PodCIDR accepted")
	}
}
func TestGatewayDNSRenderer(t *testing.T) {
	r, gw := fixture(t)
	r.Options.GatewayUpstreamDNSIP = "9.9.9.9"
	gw.Status.GatewayID = 27
	gw.Status.EffectiveExclusions = []api.EffectiveExclusion{{CIDR: "10.42.0.0/16", Source: "podCIDR"}, {CIDR: "10.43.0.0/16", Source: "serviceCIDR"}}
	gw.Spec.DNS.Mode = "gateway"
	objects, err := r.render(gw, []netip.Addr{}, "10.43.0.10")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 5 {
		t.Fatalf("expected dedicated DNS Service: %d objects", len(objects))
	}
	svc := objects[3].(*corev1.Service)
	if svc.Name != "edge-dns" || !svc.Spec.PublishNotReadyAddresses || len(svc.Spec.Ports) != 2 || svc.Spec.Ports[0].Port != 53 || svc.Spec.Ports[1].Port != 53 || svc.Spec.Ports[0].TargetPort.IntVal != 1053 || len(svc.OwnerReferences) != 1 {
		t.Fatalf("DNS Service incorrect: %+v", svc)
	}
	dep := objects[2].(*appsv1.Deployment)
	if dep.Spec.Template.Spec.DNSPolicy != corev1.DNSClusterFirst {
		t.Fatal("gateway Pod DNS policy changed")
	}
	env := map[string]string{}
	for _, v := range dep.Spec.Template.Spec.Containers[0].Env {
		env[v.Name] = v.Value
	}
	if env["CLUSTER_DNS_IP"] != "10.43.0.10" || env["GATEWAY_DNS_LISTEN_ADDR"] != ":1053" || env["CLUSTER_DOMAIN"] != "cluster.local" || env["CLUSTER_CIDRS"] != "10.42.0.0/16,10.43.0.0/16" || env["UPSTREAM_DNS_IP"] != "9.9.9.9" {
		t.Fatalf("gateway DNS env incorrect: %+v", env)
	}
	if _, err := r.render(gw, nil); err == nil {
		t.Fatal("gateway DNS accepted unknown resolver")
	}
	r.Options.GatewayUpstreamDNSIP = "invalid"
	if _, err := r.render(gw, nil, "10.43.0.10"); err == nil {
		t.Fatal("invalid upstream DNS IP accepted")
	}

}

func TestGatewayIngressNetworkPolicy(t *testing.T) {
	r, gw := fixture(t)
	gw.Status.GatewayID = 17
	gw.Status.EffectiveExclusions = []api.EffectiveExclusion{{CIDR: "10.42.0.0/16", Source: "podCIDR"}, {CIDR: "10.43.0.0/16", Source: "serviceCIDR"}}
	gw.Spec.DNS.Mode = "gateway"
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}
	objects, err := r.render(gw, nil, "10.43.0.10")
	if err != nil {
		t.Fatal(err)
	}
	policy := objects[len(objects)-1].(*networkingv1.NetworkPolicy)
	if len(policy.OwnerReferences) != 1 || policy.Spec.PodSelector.MatchLabels[GatewayLabel] != "" || policy.Spec.PodSelector.MatchLabels[IdentityLabel] != "edge" {
		t.Fatal("NP does not isolate gateway identity")
	}
	if len(policy.Spec.PolicyTypes) != 1 || policy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress || len(policy.Spec.Egress) != 0 || len(policy.Spec.Ingress) != 3 {
		t.Fatalf("gateway egress blocked or ingress missing: %+v", policy.Spec)
	}
	health := policy.Spec.Ingress[0]
	if len(health.From) != 0 || health.Ports[0].Port.IntVal != 9900 || *health.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Fatal("controller/kubelet health blocked")
	}
	for i, ports := range [][]int32{{6081}, {1053, 1053}} {
		rule := policy.Spec.Ingress[i+1]
		if len(rule.From) != 1 || rule.From[0].NamespaceSelector.MatchLabels["team"] != "red" || rule.From[0].PodSelector.MatchLabels[GatewayLabel] != "edge" {
			t.Fatalf("traffic selector too broad: %+v", rule)
		}
		if len(rule.Ports) != len(ports) {
			t.Fatal("unexpected ingress ports")
		}
		for j, port := range ports {
			if rule.Ports[j].Port.IntVal != port {
				t.Fatalf("port %d != %d", rule.Ports[j].Port.IntVal, port)
			}
		}
	}
	gw.Spec.DNS.Mode = "cluster"
	gw.Spec.AllowedNamespaces.NamespaceSelector = nil
	noClients, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy = noClients[len(noClients)-1].(*networkingv1.NetworkPolicy)
	if len(policy.Spec.Ingress) != 1 || len(policy.Spec.Ingress[0].From) != 0 {
		t.Fatal("nil allowedNamespaces must deny clients")
	}
}
