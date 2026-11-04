package webhook

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestGatewayAnnotationOptInNormalizesLabelBeforeAgentAndInitAdmission(t *testing.T) {
	for _, driver := range []string{"agent", "init"} {
		t.Run(driver, func(t *testing.T) {
			ns, gw := fixture()
			h := setup(t, ns, gw)
			h.Driver = driver
			pod := optedPod()
			pod.Labels = nil
			pod.Annotations = map[string]string{GatewayLabel: "gateway"}
			out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
			if out.Labels[GatewayLabel] != "gateway" || out.Annotations[GatewayLabel] != "gateway" ||
				out.Annotations[ConfigAnnotation] == "" || out.Annotations[ReadyAnnotation] != "pending" || len(out.Spec.InitContainers) == 0 {
				t.Fatal("annotation selection did not create label-backed pending safe workload")
			}
			if driver == "agent" && out.Spec.InitContainers[0].Name != "ratatoskr-init" {
				t.Fatalf("annotation agent lost capability-free wait init: %q", out.Spec.InitContainers[0].Name)
			}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !r.Allowed {
				t.Fatalf("mutated annotation Pod denied: %v", r.Result)
			}
			if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)); r.Allowed {
				t.Fatal("annotation without mutator admitted")
			}
			bare := out.DeepCopy()
			delete(bare.Labels, GatewayLabel)
			if h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, bare, nil)).Allowed {
				t.Fatal("annotation without normalized label admitted")
			}
			for _, user := range []string{"ordinary-user", "system:serviceaccount:system:ratatoskr-agent"} {
				for _, change := range []string{"remove-annotation", "change-annotation", "remove-label", "change-label"} {
					next := out.DeepCopy()
					switch change {
					case "remove-annotation":
						delete(next.Annotations, GatewayLabel)
					case "change-annotation":
						next.Annotations[GatewayLabel] = "other"
					case "remove-label":
						delete(next.Labels, GatewayLabel)
					case "change-label":
						next.Labels[GatewayLabel] = "other"
					}
					r := req(t, "Pod", admissionv1.Update, next, &out)
					r.UserInfo.Username = user
					if h.Validate(context.Background(), r).Allowed {
						t.Fatalf("%s %s changed gateway selection", user, change)
					}
				}
			}
			// Old selected object must not become unselected via both fields changing.
			changed := out.DeepCopy()
			delete(changed.Labels, GatewayLabel)
			delete(changed.Annotations, GatewayLabel)
			if h.Validate(context.Background(), req(t, "Pod", admissionv1.Update, changed, &out)).Allowed {
				t.Fatal("both selection fields removed")
			}
		})
	}
}
func TestGatewayAnnotationConflictsAndInvalidNamesFailClosed(t *testing.T) {
	ns, gw := fixture()
	h := setup(t, ns, gw)
	h.Driver = "agent"
	for _, tc := range []struct {
		label, annotation string
		allowed           bool
	}{
		{"gateway", "gateway", true}, {"gateway", "other", false}, {"", "gateway/ns", false},
		{"", "UPPER", false}, {"", "gateway:443", false}, {"", "", true},
	} {
		pod := optedPod()
		pod.Labels = map[string]string{}
		if tc.label != "" {
			pod.Labels[GatewayLabel] = tc.label
		}
		if tc.annotation != "" {
			pod.Annotations = map[string]string{GatewayLabel: tc.annotation}
		}
		result := h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil))
		if result.Allowed != tc.allowed {
			t.Fatalf("selection %+v unexpectedly allowed=%t (%v)", tc, result.Allowed, result.Result)
		}
		if !tc.allowed && result.Result != nil && (strings.Contains(result.Result.Message, "gateway/ns") || strings.Contains(result.Result.Message, "UPPER")) {
			t.Fatal("invalid user gateway value leaked")
		}
	}
	untouched := &corev1.Pod{}
	if r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, untouched, nil)); !r.Allowed {
		t.Fatal("unselected workload affected")
	}
}
