package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestAgentDriverWaitInitSecurityAndNoToken(t *testing.T) {
	for _, encryption := range []string{"none", "wireguard"} {
		t.Run(encryption, func(t *testing.T) {
			namespace, gatewayObject := fixture()
			gateway := gatewayObject.(*v1alpha1.EgressGateway)
			gateway.Spec.Encryption = encryption
			if encryption == "wireguard" {
				gateway.Status.Endpoints = []v1alpha1.GatewayEndpoint{wgEndpoint(t)}
			}
			h := setup(t, namespace, gateway)
			h.Driver = "agent"
			h.Datapath = "iproute"
			pod := optedPod()
			fsGroup := int64(1234)
			pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &fsGroup}
			out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
			if len(out.Spec.InitContainers) != 1 || out.Spec.InitContainers[0].Image != h.InitImage || len(out.Spec.InitContainers[0].Args) != 1 || out.Spec.InitContainers[0].Args[0] != "-wait-agent" {
				t.Fatalf("wrong agent wait-init: %+v", out.Spec.InitContainers)
			}
			init := out.Spec.InitContainers[0]
			sc := init.SecurityContext
			if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.RunAsUser == nil || *sc.RunAsUser != 65532 || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
				t.Fatalf("wait-init not restricted-compatible: %+v", sc)
			}
			if len(init.Env) != 0 || len(init.VolumeMounts) != 1 || init.VolumeMounts[0].Name != agentShadowVolume || init.VolumeMounts[0].MountPath != defaultSATokenPath || len(out.Spec.Volumes) != 1 || out.Spec.Volumes[0].Name != agentShadowVolume || out.Spec.Volumes[0].EmptyDir == nil || out.Spec.SecurityContext == nil || out.Spec.SecurityContext.FSGroup == nil || *out.Spec.SecurityContext.FSGroup != fsGroup {
				t.Fatal("agent wait-init API token shadow invalid or workload fsGroup changed")
			}
			if out.Annotations[ReadyAnnotation] != "pending" || out.Annotations[ConfigAnnotation] == "" {
				t.Fatalf("agent readiness or config invalid: %+v", out.Annotations)
			}
			var cfg datapath.ClientConfig
			if err := json.Unmarshal([]byte(out.Annotations[ConfigAnnotation]), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Encryption != encryption {
				t.Fatalf("wrong encryption: %+v", cfg)
			}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
				t.Fatalf("agent mutation denied: %+v", r.Result)
			}
			forged := out.DeepCopy()
			forged.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
				t.Fatal("forged NET_ADMIN wait-init accepted")
			}
			forged = out.DeepCopy()
			forged.Spec.InitContainers[0].Args = []string{"-config=/var/run/ratatoskr/client.json"}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
				t.Fatal("forged privileged-init argument accepted")
			}
			forged = out.DeepCopy()
			forged.Spec.Volumes[0].EmptyDir = nil
			forged.Spec.Volumes[0].Secret = &corev1.SecretVolumeSource{SecretName: "forged-api-credentials"}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
				t.Fatal("forged API-token shadow backed by Secret accepted")
			}
			forged = out.DeepCopy()
			forged.Spec.InitContainers[0].VolumeMounts[0].Name = "kube-api-access-stolen"
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
				t.Fatal("forged API-token mount accepted in agent wait-init")
			}
			forged = out.DeepCopy()
			injectWireGuardToken(forged)
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); r.Allowed {
				t.Fatal("agent-mode workload token projection accepted")
			}
		})
	}
}
func TestAgentDriverOptInAndUnsupportedModes(t *testing.T) {
	namespace, gateway := fixture()
	h := setup(t, namespace, gateway)
	h.Driver = "agent"
	pod := optedPod()
	delete(pod.Labels, GatewayLabel)
	if r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); !r.Allowed {
		t.Fatalf("unlabeled pod rejected: %+v", r.Result)
	}
	pod = optedPod()
	for _, driver := range []string{"agent", "init"} {
		h.Driver = driver
		h.Datapath = "ebpf"
		out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
		if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
			t.Fatalf("ebpf driver %s rejected at validating admission: %+v", driver, r.Result)
		}
	}
	h.Driver = "agent"
	h.Datapath = "not-a-datapath"
	if r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); r.Allowed || !strings.Contains(r.Result.Message, "unsupported DATAPATH") {
		t.Fatalf("invalid datapath admitted: %+v", r.Result)
	}
	h.Datapath = "iproute"
	h.Driver = "mystery"
	if r := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); r.Allowed || !strings.Contains(r.Result.Message, "unsupported DRIVER") {
		t.Fatalf("unsupported driver admitted: %+v", r.Result)
	}
}
