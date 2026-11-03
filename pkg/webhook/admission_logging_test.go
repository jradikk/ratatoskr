package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func TestStructuredAdmissionDecisionsAreCategorizedWithoutPrivateInput(t *testing.T) {
	ns, gateway := fixture()
	h := setup(t, ns, gateway)
	h.Driver = "agent"
	pod := optedPod()
	pod.Name = ""
	pod.GenerateName = "client-"
	record := mutatedPod(t, h.MutatePod(context.Background(), req(t, "Pod", admissionv1.Create, pod, nil)), pod)
	record.Name = "client-abcde"
	record.UID = "server-assigned-uid"
	request := req(t, "Pod", admissionv1.Create, &record, nil)
	request.UID = "2d0566ae-30f0-46fa-8208-8c0b9bc5e759"
	var logs bytes.Buffer
	h.Logger = logr.FromSlogHandler(slog.NewJSONHandler(&logs, nil))
	allowed := h.Validate(context.Background(), request)
	if !allowed.Allowed {
		t.Fatalf("generated Pod rejected: %v", allowed.Result)
	}
	var log map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &log); err != nil {
		t.Fatal(err)
	}
	if log["requestUID"] != string(request.UID) || log["stage"] != "validate" || log["category"] != "allowed" || log["allowed"] != true {
		t.Fatalf("missing sanitized admission identity/outcome: %v", log)
	}
	for _, forged := range []struct {
		name   string
		mutate func(*datapath.ClientConfig)
	}{
		{"identity-pod", func(c *datapath.ClientConfig) { c.Identity.Pod = "SECRET_PRIVATE_POD" }},
		{"identity-namespace", func(c *datapath.ClientConfig) { c.Identity.Namespace = "SECRET_PRIVATE_NAMESPACE" }},
	} {
		logs.Reset()
		copy := record.DeepCopy()
		var cfg datapath.ClientConfig
		if err := json.Unmarshal([]byte(copy.Annotations[ConfigAnnotation]), &cfg); err != nil {
			t.Fatal(err)
		}
		forged.mutate(&cfg)
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		copy.Annotations[ConfigAnnotation] = string(raw)
		r := h.Validate(context.Background(), req(t, "Pod", admissionv1.Create, copy, nil))
		if r.Allowed || !strings.Contains(r.Result.Message, "("+forged.name+")") {
			t.Fatal("forged config accepted or category missing")
		}
		if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &log); err != nil {
			t.Fatal(err)
		}
		if log["category"] != forged.name || log["allowed"] != false || strings.Contains(logs.String(), "SECRET_PRIVATE_") || strings.Contains(logs.String(), "client-config") {
			t.Fatalf("unsafe admission log: %q", logs.String())
		}
	}
	// Unknown denial details must never enter the structured log.
	logs.Reset()
	h.auditAdmission(context.Background(), request, "validate", admission.Denied("PRIVATE_TOKEN_MUST_NOT_LOG"))
	if strings.Contains(logs.String(), "PRIVATE_TOKEN") || !strings.Contains(logs.String(), "denied-other") {
		t.Fatalf("unknown admission error leaked: %s", logs.String())
	}
}
