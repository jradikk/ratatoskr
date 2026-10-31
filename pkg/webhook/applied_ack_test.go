package webhook

import (
	"context"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
)

func TestInitAppliedAckControllerWriterAndProjection(t *testing.T) {
	ns, gw := fixture()
	h := setup(t, ns, gw)
	h.Driver = "init"
	p := optedPod()
	out := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)), p)
	if _, ok := out.Annotations[appliedAckAnnotation]; !ok || out.Annotations[appliedAckAnnotation] != "" {
		t.Fatal("init applied ack not initialized pending")
	}
	init := out.Spec.InitContainers[0]
	if len(init.VolumeMounts) == 0 || init.VolumeMounts[0].Name != configVolume {
		t.Fatal("init lacks projected config volume")
	}
	found := false
	for _, v := range out.Spec.Volumes {
		if v.Name == configVolume {
			found = true
			if v.DownwardAPI == nil || len(v.DownwardAPI.Items) != 2 || v.DownwardAPI.Items[1].Path != "applied-ack.json" {
				t.Fatal("ack not projected separately")
			}
		}
	}
	if !found {
		t.Fatal("no projected ack volume")
	}
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, &out, nil)); !response.Allowed {
		t.Fatalf("safe init denied: %+v", response.Result)
	}
	forged := out.DeepCopy()
	forged.Annotations[appliedAckAnnotation] = `{"workloadUID":"forged"}`
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, forged, nil)); response.Allowed {
		t.Fatal("forged initial ack admitted")
	}
	changed := out.DeepCopy()
	changed.Annotations[appliedAckAnnotation] = `{"workloadUID":"uid"}`
	for _, username := range []string{"ordinary-user", "system:serviceaccount:system:ratatoskr-agent", "system:serviceaccount:other:ratatoskr-controller"} {
		r := req(t, "Pod", admissionv1.Update, changed, &out)
		r.UserInfo.Username = username
		if h.Validate(context.Background(), r).Allowed {
			t.Fatalf("unauthorized ack writer %q accepted", username)
		}
	}
	r := req(t, "Pod", admissionv1.Update, changed, &out)
	r.UserInfo.Username = "system:serviceaccount:system:ratatoskr-controller"
	if response := h.Validate(context.Background(), r); !response.Allowed {
		t.Fatalf("controller ack writer denied: %+v", response.Result)
	}
	projected := out.DeepCopy()
	projected.Spec.Volumes[0].DownwardAPI.Items[1].FieldRef.FieldPath = "metadata.annotations['other']"
	if response := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, projected, nil)); response.Allowed {
		t.Fatal("forged ack projection accepted")
	}
	agent := setup(t, ns, gw)
	agent.Driver = "agent"
	wait := mutatedPod(t, agent.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, p, nil)), p)
	if _, ok := wait.Annotations[appliedAckAnnotation]; ok {
		t.Fatal("agent driver received init ack")
	}
}
