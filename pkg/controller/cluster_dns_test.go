package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestClusterDNSAddressOverrideAndClusterFirstResolver(t *testing.T) {
	r, _ := fixture(t)
	for _, tc := range []struct{ name, override, resolver, want, code string }{
		{"literal Service VIP", "10.96.0.10", "nameserver 8.8.8.8\n", "10.96.0.10", ""},
		{"NodeLocal resolver", "169.254.20.10", "nameserver 10.96.0.10\n", "169.254.20.10", ""},
		{"controller ClusterFirst resolver", "", "# comment\nsearch svc.cluster.local\nnameserver 169.254.20.10\n", "169.254.20.10", ""},
		{"skip unusable first", "", "nameserver ::1\nnameserver 127.0.0.1\nnameserver 10.110.0.10\n", "10.110.0.10", ""},
		{"invalid override", "localhost", "nameserver 10.96.0.10\n", "", "ClusterDNSInvalid"},
		{"loopback override", "127.0.0.1", "nameserver 10.96.0.10\n", "", "ClusterDNSInvalid"},
		{"external-only invalid resolver", "", "nameserver 127.0.0.1\n", "", "ClusterDNSUnknown"},
		{"missing nameserver", "", "search svc.cluster.local\n", "", "ClusterDNSUnknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.Options.ClusterDNSIP = tc.override
			r.ReadResolver = func() ([]byte, error) { return []byte(tc.resolver), nil }
			addr, err := r.clusterDNSAddress()
			if tc.code == "" {
				if err != nil || addr.String() != tc.want {
					t.Fatalf("address %v %v want %s", addr, err, tc.want)
				}
				return
			}
			code, message := exclusionAdvice(err)
			if code != tc.code || strings.Contains(message, "SECRET") {
				t.Fatalf("unexpected safe category %s: %s", code, message)
			}
		})
	}
	r.Options.ClusterDNSIP = ""
	r.ReadResolver = func() ([]byte, error) { return nil, errors.New("SECRET-TOKEN-URL") }
	_, err := r.clusterDNSAddress()
	code, message := exclusionAdvice(err)
	if code != "ClusterDNSUnknown" || strings.Contains(message, "SECRET-TOKEN-URL") {
		t.Fatal("resolver read error leaked")
	}
}
func TestClusterDNSLabeledServicesAndNodeLocalFallback(t *testing.T) {
	r, gw := fixture(t)
	ctx := context.Background()
	gw.Spec.DNS.Mode = "gateway"
	if err := r.Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "dns-core", Namespace: "custom-system", Labels: map[string]string{"app.kubernetes.io/name": "coredns"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.90.0.15"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "dns-core-1", Namespace: "custom-system", Labels: map[string]string{discoveryv1.LabelServiceName: "dns-core"}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.42.0.20"}}}}); err != nil {
		t.Fatal(err)
	}
	r.Options.ClusterDNSIP = ""
	r.ReadResolver = func() ([]byte, error) { return []byte("nameserver 169.254.20.10\n"), nil }
	exclusions, dns, err := r.collectExclusions(ctx, gw)
	if err != nil {
		t.Fatal(err)
	}
	if dns != "169.254.20.10" || !containsExclusion(exclusions, "169.254.20.10/32", "dns") || !containsExclusion(exclusions, "10.90.0.15/32", "dns") || !containsExclusion(exclusions, "10.42.0.20/32", "dns") {
		t.Fatalf("labeled DNS and NodeLocal exclusion missing: %s %+v", dns, exclusions)
	}
	r.Options.ClusterDNSIP = "10.96.0.9"
	exclusions, dns, err = r.collectExclusions(ctx, gw)
	if err != nil || dns != "10.96.0.9" || !containsExclusion(exclusions, "10.96.0.9/32", "dns") {
		t.Fatalf("explicit DNS override lost: %s %v", dns, err)
	}
	// This namespaced custom Service replaces hardcoded kube-system/kube-dns.
	r.Options.ClusterDNSIP = ""
	r.ReadResolver = func() ([]byte, error) { return []byte("nameserver ::1\n"), nil }
	if _, _, err := r.collectExclusions(ctx, gw); err == nil {
		t.Fatal("unusable resolver admitted")
	}
}
func TestNoHardcodedKubeDNSServiceRequired(t *testing.T) {
	r, gw := fixture(t)
	r.Options.ClusterDNSIP = ""
	r.ReadResolver = func() ([]byte, error) { return []byte("nameserver 10.96.0.10\n"), nil }
	_, dns, err := r.collectExclusions(context.Background(), gw)
	if err != nil || dns != "10.96.0.10" {
		t.Fatalf("missing named kube-dns Service unexpectedly blocked: %v %s", err, dns)
	}
}
