package webhook

import (
	"context"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
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

func TestWireGuardAdmissionFailClosedBeforeDatapathFields(t *testing.T) {
	namespace, object := fixture()
	gateway := object.(*v1alpha1.EgressGateway)
	gateway.Spec.Encryption = "wireguard"
	gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{wgEndpoint(t)}
	h := setup(t, namespace, gateway)
	pod := optedPod()
	r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
	if r.Allowed || !strings.Contains(r.Result.Message, "datapath fields are not available") {
		t.Fatalf("WG endpoint accepted before config fields: %+v", r.Result)
	}
	gateway.Status.Endpoints[0].WireguardPublicKey = "wrong-key"
	h = setup(t, namespace, gateway)
	r = h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
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
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
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
