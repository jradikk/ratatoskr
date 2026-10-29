package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func wgEndpoint(t *testing.T) v1alpha1.GatewayEndpoint {
	t.Helper()
	ca, _, _, _, err := newIdentity("gateway.svc", "gateway.svc.cluster.local")
	if err != nil {
		t.Fatal(err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return v1alpha1.GatewayEndpoint{PodIP: "10.1.2.3", UpstreamHealthy: true, WireguardPublicKey: key.PublicKey().String(), RegistrationCACert: string(ca)}
}
func TestWireGuardEndpointPublicMaterial(t *testing.T) {
	endpoint := wgEndpoint(t)
	if err := validateWireGuardEndpoint(&endpoint); err != nil {
		t.Fatal(err)
	}
	invalid := endpoint
	invalid.WireguardPublicKey = "not-a-key"
	if err := validateWireGuardEndpoint(&invalid); err == nil || strings.Contains(err.Error(), "not-a-key") {
		t.Fatalf("invalid key not rejected safely: %v", err)
	}
	invalid = endpoint
	invalid.RegistrationCACert = ""
	if err := validateWireGuardEndpoint(&invalid); err == nil {
		t.Fatal("missing registration CA allowed")
	}
	invalid = endpoint
	invalid.RegistrationCACert = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
	if err := validateWireGuardEndpoint(&invalid); err == nil {
		t.Fatal("malformed registration CA allowed")
	}
}
func TestProjectedTokenInitOnly(t *testing.T) {
	pod := optedPod()
	pod.Spec.InitContainers = []corev1.Container{{Name: initName, Image: "ratatoskr:init"}, {Name: "other", Image: "other"}}
	fsGroup := int64(1234)
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &fsGroup}
	injectWireGuardToken(pod)
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].Projected == nil {
		t.Fatal("projected token missing")
	}
	if pod.Spec.Volumes[0].Projected.DefaultMode == nil || *pod.Spec.Volumes[0].Projected.DefaultMode != 0444 {
		t.Fatal("non-root init cannot read projected token with expected 0444 mode")
	}
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil || *pod.Spec.SecurityContext.FSGroup != fsGroup {
		t.Fatal("token projection changed workload fsGroup")
	}
	token := pod.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken
	if token == nil || token.Audience != wgTokenAudience || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 600 || token.Path != "token" {
		t.Fatalf("wrong projected token settings: %+v", token)
	}
	if len(pod.Spec.InitContainers[0].VolumeMounts) != 1 || pod.Spec.InitContainers[0].VolumeMounts[0].MountPath != wgTokenMount || len(pod.Spec.InitContainers[1].VolumeMounts) != 0 || len(pod.Spec.Containers[0].VolumeMounts) != 0 {
		t.Fatal("token leaked outside Ratatoskr init")
	}
	// The validator expects the existing client config mount first.
	pod.Spec.InitContainers[0].VolumeMounts = append([]corev1.VolumeMount{{Name: configVolume, MountPath: "/var/run/ratatoskr", ReadOnly: true}}, pod.Spec.InitContainers[0].VolumeMounts...)
	if err := validateWireGuardToken(pod); err != nil {
		t.Fatal(err)
	}
	pod.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "wrong-audience"
	if err := validateWireGuardToken(pod); err == nil {
		t.Fatal("wrong audience accepted")
	}
	pod.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = wgTokenAudience
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: wgTokenMount}}
	if err := validateWireGuardToken(pod); err == nil {
		t.Fatal("workload token mount accepted")
	}
}

func TestWireGuardAffinityKeepsSelectedIdentityOnReorder(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Spec.Replicas = 3
	gateway.Spec.Encryption = "wireguard"
	first := wgEndpoint(t)
	second := wgEndpoint(t)
	second.PodIP = "10.1.2.4"
	gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{first, second}
	h := setup(t, namespace, gateway)
	pod := optedPod()
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	var selected v1alpha1.GatewayEndpoint
	for _, endpoint := range gateway.Status.Endpoints {
		if cfg.Endpoint.String() == endpoint.PodIP {
			selected = endpoint
		}
	}
	if selected.PodIP == "" || cfg.GatewayPublicKey != selected.WireguardPublicKey || cfg.RegistrationCACert != selected.RegistrationCACert {
		t.Fatal("selected endpoint WG identity mismatch")
	}
	gateway.Status.Endpoints[0], gateway.Status.Endpoints[1] = gateway.Status.Endpoints[1], gateway.Status.Endpoints[0]
	h = setup(t, namespace, gateway)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("WG identity changed on status reorder: %+v", r.Result)
	}
	forged := out.DeepCopy()
	cfg.GatewayPublicKey = first.WireguardPublicKey
	if selected.PodIP == first.PodIP {
		cfg.GatewayPublicKey = second.WireguardPublicKey
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	forged.Annotations[ConfigAnnotation] = string(raw)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("wrong replica public identity accepted")
	}
}

func TestWireGuardTokenPreexistingMountRejected(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Spec.Encryption = "wireguard"
	gateway.Status.Endpoints = nil // no endpoint remains fail-closed, but still projects the token
	h := setup(t, namespace, gateway)
	cases := []struct {
		name string
		add  func(*corev1.Pod)
	}{
		{"app", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: "/tmp/stolen"}}
		}},
		{"other init", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "other", Image: "other", VolumeMounts: []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: "/tmp/stolen"}}}}
		}},
		{"ephemeral", func(p *corev1.Pod) {
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "other", Image: "other", VolumeMounts: []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: "/tmp/stolen"}}}}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := optedPod()
			tc.add(pod)
			response := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
			if response.Allowed || !strings.Contains(response.Result.Message, "reserved WireGuard token mount") {
				t.Fatalf("preexisting %s mount exposed token: %+v", tc.name, response.Result)
			}
		})
	}
}

func TestWireGuardTokenForgedExtraMountRejected(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Spec.Encryption = "wireguard"
	gateway.Status.Endpoints = nil
	h := setup(t, namespace, gateway)
	pod := optedPod()
	mutated := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	cases := []struct {
		name string
		add  func(*corev1.Pod)
	}{
		{"app", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: "/tmp/stolen"}}
		}},
		{"other init", func(p *corev1.Pod) {
			p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: "other", Image: "other", VolumeMounts: []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: "/tmp/stolen"}}})
		}},
		{"ephemeral", func(p *corev1.Pod) {
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "other", Image: "other", VolumeMounts: []corev1.VolumeMount{{Name: wgTokenVolume, MountPath: "/tmp/stolen"}}}}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forged := mutated.DeepCopy()
			tc.add(forged)
			response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil))
			if response.Allowed || !strings.Contains(response.Result.Message, "WireGuard token must not be mounted") {
				t.Fatalf("forged %s mount exposed token: %+v", tc.name, response.Result)
			}
		})
	}
}

func TestWireGuardAdmissionPinsHealthyEndpointAndFailsClosedWithoutOne(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Spec.Encryption = "wireguard"
	gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{wgEndpoint(t)}
	h := setup(t, namespace, gateway)
	pod := optedPod()
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Encryption != "wireguard" || cfg.Endpoint.String() != gateway.Status.Endpoints[0].PodIP || cfg.GatewayPublicKey != gateway.Status.Endpoints[0].WireguardPublicKey || cfg.RegistrationCACert != gateway.Status.Endpoints[0].RegistrationCACert || cfg.WireGuardPort != datapath.WireGuardPortDefault {
		t.Fatal("healthy WireGuard endpoint public identity not pinned to selected PodIP")
	}
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("correctly pinned WireGuard pod denied: %+v", r.Result)
	}
	forged := out.DeepCopy()
	cfg.GatewayPublicKey = wgEndpoint(t).WireguardPublicKey
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	forged.Annotations[ConfigAnnotation] = string(raw)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("forged gateway public key accepted")
	}
	forged = out.DeepCopy()
	cfg.GatewayPublicKey = gateway.Status.Endpoints[0].WireguardPublicKey
	cfg.RegistrationCACert = wgEndpoint(t).RegistrationCACert
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	forged.Annotations[ConfigAnnotation] = string(raw)
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
		t.Fatal("forged registration CA pin accepted")
	}
	gateway.Status.Endpoints[0].WireguardPublicKey = "wrong-key"
	h = setup(t, namespace, gateway)
	r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "public key") {
		t.Fatalf("malformed WG endpoint key accepted: %+v", r.Result)
	}
	gateway.Status.Endpoints[0] = wgEndpoint(t)
	gateway.Status.Endpoints[0].RegistrationCACert = ""
	h = setup(t, namespace, gateway)
	r = h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "registration CA") {
		t.Fatalf("missing WG CA accepted: %+v", r.Result)
	}
	gateway.Status.Endpoints = nil
	h = setup(t, namespace, gateway)
	out = mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	var missing datapath.ClientConfig
	if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &missing); err != nil {
		t.Fatal(err)
	}
	if missing.Endpoint.IsValid() || missing.GatewayPublicKey != "" || missing.RegistrationCACert != "" || missing.WireGuardPort != 0 {
		t.Fatal("no-endpoint config leaked another gateway's public identity")
	}
	if len(out.Spec.InitContainers[0].VolumeMounts) != 2 || len(out.Spec.Containers[0].VolumeMounts) != 0 || !strings.Contains(out.Annotations[ConfigAnnotation], `"encryption":"wireguard"`) {
		t.Fatalf("failclosed WG config or token mount missing: %+v", out.Spec.InitContainers[0].VolumeMounts)
	}
	var projected *corev1.ProjectedVolumeSource
	for _, volume := range out.Spec.Volumes {
		if volume.Name == wgTokenVolume {
			projected = volume.Projected
		}
	}
	if projected == nil || projected.DefaultMode == nil || *projected.DefaultMode != 0444 || len(projected.Sources) != 1 || projected.Sources[0].ServiceAccountToken == nil {
		t.Fatal("rendered Pod lacks readable init-only projected gateway token")
	}
	if strings.Contains(out.Annotations[ConfigAnnotation], wgTokenAudience) || strings.Contains(out.Annotations[ConfigAnnotation], wgTokenVolume) {
		t.Fatal("token metadata was embedded into client annotation")
	}
	if r = h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
		t.Fatalf("failclosed WG init rejected: %+v", r.Result)
	}
}
