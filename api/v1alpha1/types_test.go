package v1alpha1

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestJSONRoundTrip(t *testing.T) {
	original := &EgressGateway{
		TypeMeta:   metav1.TypeMeta{APIVersion: SchemeGroupVersion.String(), Kind: "EgressGateway"},
		ObjectMeta: metav1.ObjectMeta{Name: "exit", Namespace: "ops", Labels: map[string]string{"region": "west"}},
		Spec: EgressGatewaySpec{
			Replicas: 2, Encryption: "wireguard", Affinity: "per-pod", FailMode: "closed",
			Upstream:          UpstreamSpec{Type: "custom", Image: "registry.example/connector:v1", SecretRef: SecretReference{Name: "vpn-config"}},
			AllowedNamespaces: AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"egress": "allowed"}}},
			Exclusions:        ExclusionsSpec{ExtraCIDRs: []string{"10.0.0.0/8"}},
		},
		Status: EgressGatewayStatus{GatewayID: 42, Endpoints: []GatewayEndpoint{{PodIP: "10.2.0.3", PodUID: "gateway-pod-uid", AppliedClientConfigHash: strings.Repeat("a", 64), UpstreamExitIP: "203.0.113.4", UpstreamHealthy: true, WireguardPublicKey: "public-key", RegistrationCACert: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"}}},
	}
	policy := &EgressPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: SchemeGroupVersion.String(), Kind: "EgressPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "apps"},
		Spec:       EgressPolicySpec{GatewayRef: GatewayReference{Name: "exit", Namespace: "ops"}, WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Mode: "include", Rules: []EgressRule{{CIDRs: []string{"0.0.0.0/0"}, Ports: []EgressPort{{Protocol: "TCP", Port: 443}}}}},
	}
	for _, obj := range []runtime.Object{original, policy} {
		encoded, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if obj == original && !strings.Contains(string(encoded), `"registrationCACert":"-----BEGIN CERTIFICATE-----`) {
			t.Fatalf("gateway JSON omitted the registration CA certificate: %s", encoded)
		}
		if obj == original && (!strings.Contains(string(encoded), `"podUID":"gateway-pod-uid"`) ||
			!strings.Contains(string(encoded), `"appliedClientConfigHash":"`+strings.Repeat("a", 64)+`"`)) {
			t.Fatalf("gateway JSON omitted the applied config acknowledgment: %s", encoded)
		}
		decoded := reflect.New(reflect.TypeOf(obj).Elem()).Interface()
		if err := json.Unmarshal(encoded, decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(obj, decoded) {
			t.Fatalf("JSON round-trip mismatch for %T: %s", obj, encoded)
		}
	}
}

func TestRuntimeDeepCopy(t *testing.T) {
	autoDetect := true
	gateway := &EgressGateway{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"team": "a"}}, Spec: EgressGatewaySpec{AllowedNamespaces: AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}}, Exclusions: ExclusionsSpec{AutoDetect: &autoDetect, ExtraCIDRs: []string{"10.0.0.0/8"}}}, Status: EgressGatewayStatus{Endpoints: []GatewayEndpoint{{PodIP: "10.0.0.1", RegistrationCACert: "public-CA"}}}}
	copied := gateway.DeepCopyObject().(*EgressGateway)
	copied.Labels["team"] = "b"
	copied.Spec.Exclusions.ExtraCIDRs[0] = "192.0.2.0/24"
	copied.Status.Endpoints[0].RegistrationCACert = "different-CA"
	copied.Spec.AllowedNamespaces.NamespaceSelector.MatchLabels["team"] = "b"
	*copied.Spec.Exclusions.AutoDetect = false
	if gateway.Labels["team"] != "a" || gateway.Spec.Exclusions.ExtraCIDRs[0] != "10.0.0.0/8" || gateway.Spec.AllowedNamespaces.NamespaceSelector.MatchLabels["team"] != "a" || !*gateway.Spec.Exclusions.AutoDetect || gateway.Status.Endpoints[0].RegistrationCACert != "public-CA" {
		t.Fatal("gateway copy aliases original")
	}
	policy := &EgressPolicy{Spec: EgressPolicySpec{Rules: []EgressRule{{Ports: []EgressPort{{Protocol: "TCP", Port: 80}}}}, WorkloadSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	policyCopy := policy.DeepCopyObject().(*EgressPolicy)
	policyCopy.Spec.Rules[0].Ports[0].Port = 443
	policyCopy.Spec.WorkloadSelector.MatchLabels["app"] = "other"
	if policy.Spec.Rules[0].Ports[0].Port != 80 || policy.Spec.WorkloadSelector.MatchLabels["app"] != "web" {
		t.Fatal("policy copy aliases original")
	}
	for _, obj := range []runtime.Object{(&EgressGatewayList{Items: []EgressGateway{*gateway}}).DeepCopyObject(), (&EgressPolicyList{Items: []EgressPolicy{*policy}}).DeepCopyObject()} {
		if obj == nil {
			t.Fatal("nil runtime list copy")
		}
	}
}

func TestSchemeAndResources(t *testing.T) {
	if GroupName != "ratatoskr.skaldhall.io" || Resource("egressgateways").String() != "egressgateways.ratatoskr.skaldhall.io" || Resource("egresspolicies").String() != "egresspolicies.ratatoskr.skaldhall.io" {
		t.Fatal("unexpected group or resource names")
	}
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		obj  runtime.Object
		kind string
	}{{&EgressGateway{}, "EgressGateway"}, {&EgressGatewayList{}, "EgressGatewayList"}, {&EgressPolicy{}, "EgressPolicy"}, {&EgressPolicyList{}, "EgressPolicyList"}} {
		gvks, _, err := scheme.ObjectKinds(tc.obj)
		if err != nil || len(gvks) != 1 || gvks[0] != SchemeGroupVersion.WithKind(tc.kind) {
			t.Fatalf("kind for %T: %v: %v", tc.obj, gvks, err)
		}
		if _, err := scheme.New(gvks[0]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileJSONAndDeepCopy(t *testing.T) {
	gateway := &EgressGateway{Spec: EgressGatewaySpec{Upstream: UpstreamSpec{Type: "openvpn", Profiles: []UpstreamProfile{{Name: "berlin", SecretRef: SecretReference{Name: "berlin-secret"}}, {Name: "oslo", SecretRef: SecretReference{Name: "oslo-secret"}}}}}}
	raw, err := json.Marshal(gateway)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"secretRef":{}`) || !strings.Contains(string(raw), `"profiles"`) {
		t.Fatalf("legacy secretRef unexpectedly serialized or profiles absent: %s", raw)
	}
	decoded := &EgressGateway{}
	if err := json.Unmarshal(raw, decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Spec.Upstream.Profiles, gateway.Spec.Upstream.Profiles) {
		t.Fatal("profile round-trip changed")
	}
	copy := gateway.DeepCopy()
	copy.Spec.Upstream.Profiles[0].SecretRef.Name = "new-secret"
	if gateway.Spec.Upstream.Profiles[0].SecretRef.Name != "berlin-secret" {
		t.Fatal("profile deep-copy alias")
	}
}
