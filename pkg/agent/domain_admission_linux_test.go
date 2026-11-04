//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	webhook "github.com/skaldhall/ratatoskr/pkg/webhook"
)

// webhookPatch intercepts the exact MergeFromWithOptimisticLock patch the
// production domain worker sends. It validates old/new Pod objects with the
// real webhook Handler before letting the fake Kubernetes client persist it.
type webhookPatch struct {
	client.Client
	validator *webhook.Handler
	username  string
	calls     int
	conflicts int
	replace   func(*corev1.Pod)
}

func (w *webhookPatch) Patch(ctx context.Context, obj client.Object, patch client.Patch, options ...client.PatchOption) error {
	current := &corev1.Pod{}
	if err := w.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
		return err
	}
	rawOld, err := json.Marshal(current)
	if err != nil {
		return err
	}
	data, err := patch.Data(obj)
	if err != nil {
		return err
	}
	rawNew, err := jsonpatch.MergePatch(rawOld, data)
	if err != nil {
		return err
	}
	newPod := &corev1.Pod{}
	if err = json.Unmarshal(rawNew, newPod); err != nil {
		return err
	}
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID: types.UID("fixed-test-request-uid"), Namespace: current.Namespace,
		Kind: metav1.GroupVersionKind{Kind: "Pod", Version: "v1"}, Operation: admissionv1.Update,
		Object: runtime.RawExtension{Raw: rawNew}, OldObject: runtime.RawExtension{Raw: rawOld}}}
	req.UserInfo.Username = w.username
	result := w.validator.Validate(ctx, req)
	w.calls++
	if !result.Allowed {
		return fmt.Errorf("webhook refused exact patch: %s", result.Result.Message)
	}
	if w.conflicts > 0 {
		w.conflicts--
		if w.replace != nil {
			updated := current.DeepCopy()
			w.replace(updated)
			if err := w.Update(ctx, updated); err != nil {
				return err
			}
		}
		return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, current.Name, errors.New("synthetic stale resourceVersion"))
	}
	return w.Client.Patch(ctx, obj, patch, options...)
}

func TestAgentDomainStatePersistenceRetriesOnlyStatusResourceVersionConflicts(t *testing.T) {
	for _, conflicts := range []int{1, 2} {
		t.Run(fmt.Sprintf("conflicts-%d", conflicts), func(t *testing.T) {
			r, p, _, _, cfg, _, _, _ := domainFixture(t, "include")
			intercepted := &webhookPatch{Client: r.Client,
				validator: &webhook.Handler{Driver: "agent", AgentNamespace: "operator"},
				username:  "system:serviceaccount:operator:ratatoskr-agent", conflicts: conflicts,
				replace: func(p *corev1.Pod) { p.Status.Phase = corev1.PodRunning }}
			r.Client = intercepted
			cfg.DomainState = []datapath.DomainBinding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 100, Retained: true}}
			if err := r.patchDomainReady(context.Background(), p, cfg, "iproute"); err != nil {
				t.Fatalf("status-only resourceVersion conflict poisoned persisted state: %v", err)
			}
			if intercepted.calls != conflicts+1 {
				t.Fatalf("wanted %d bounded PATCH attempts; got %d", conflicts+1, intercepted.calls)
			}
			var current corev1.Pod
			if err := r.Client.Get(context.Background(), client.ObjectKeyFromObject(p), &current); err != nil {
				t.Fatal(err)
			}
			if current.Annotations[HashAnnotation] != HashForMode(cfg, "iproute") || current.Annotations[ReadyAnnotation] != "true" {
				t.Fatal("fresh owned state not persisted")
			}
		})
	}
}

func TestAgentDomainStatePersistenceRefusesChangedAuthorizationAfterConflict(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Pod){
		"uid":   func(p *corev1.Pod) { p.UID = "replaced" },
		"dns":   func(p *corev1.Pod) { p.Spec.DNSConfig.Nameservers[0] = "192.0.2.99" },
		"label": func(p *corev1.Pod) { p.Labels[GatewayLabel] = "other" },
		"client-config": func(p *corev1.Pod) {
			p.Annotations = copyAnnotations(p.Annotations)
			p.Annotations[webhook.ConfigAnnotation] = "forged"
		},
		"agent-state": func(p *corev1.Pod) {
			p.Annotations = copyAnnotations(p.Annotations)
			p.Annotations[HashAnnotation] = "foreign"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, p, _, _, cfg, _, _, _ := domainFixture(t, "include")
			intercepted := &webhookPatch{Client: r.Client,
				validator: &webhook.Handler{Driver: "agent", AgentNamespace: "operator"},
				username:  "system:serviceaccount:operator:ratatoskr-agent", conflicts: 1, replace: mutate}
			r.Client = intercepted
			err := r.patchDomainReady(context.Background(), p, cfg, "iproute")
			if err == nil || intercepted.calls != 1 || !strings.Contains(err.Error(), "authorization changed") {
				t.Fatalf("unsafe changed Pod retried after conflict: %v (calls=%d)", err, intercepted.calls)
			}
		})
	}
}

func TestAgentDomainStatePersistenceTraversesRealWebhookValidation(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			reconciler, p, _, _, cfg, _, _, _ := domainFixture(t, mode)
			validator := &webhook.Handler{Driver: "agent", AgentNamespace: "operator"}
			intercepted := &webhookPatch{Client: reconciler.Client, validator: validator, username: "system:serviceaccount:operator:ratatoskr-agent"}
			reconciler.Client = intercepted
			cfg.DomainState = []datapath.DomainBinding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.7"), ExpiresAt: 100, Retained: mode == "include"}}
			if err := reconciler.patchDomainReady(context.Background(), p, cfg, "iproute"); err != nil {
				t.Fatalf("domain persisted state rejected: %v", err)
			}
			var current corev1.Pod
			if err := reconciler.Client.Get(context.Background(), client.ObjectKeyFromObject(p), &current); err != nil {
				t.Fatal(err)
			}
			if intercepted.calls != 1 || current.Annotations[ConfigAnnotation] == "" || current.Annotations[HashAnnotation] != HashForMode(cfg, "iproute") || current.Annotations[ReadyAnnotation] != "true" {
				t.Fatal("webhook did not persist complete agent-owned state")
			}
			// The selected Pod's admission-time client config remains byte-for-byte
			// unchanged; only the authenticated node agent can write agent state.
			if current.Annotations[webhook.ConfigAnnotation] != "" {
				t.Fatal("agent changed immutable webhook client config")
			}
			for _, user := range []string{"ordinary-user", "system:serviceaccount:wrong:ratatoskr-agent"} {
				denied := &webhookPatch{Client: intercepted.Client, validator: validator, username: user}
				reconciler.Client = denied
				next := cfg
				next.DomainState = append([]datapath.DomainBinding(nil), cfg.DomainState...)
				next.DomainState[0].ExpiresAt++
				fresh := &corev1.Pod{}
				if err := intercepted.Get(context.Background(), client.ObjectKeyFromObject(p), fresh); err != nil {
					t.Fatal(err)
				}
				if err := reconciler.patchDomainReady(context.Background(), fresh, next, "iproute"); err == nil || !strings.Contains(err.Error(), "only the node agent") {
					t.Fatalf("incorrect agent writer authorized: %v", err)
				}
			}
			// A forged immutable client-config edit is rejected even by the genuine
			// service account; do not weaken it to fix a state-persist failure.
			reconciler.Client = intercepted
			fresh := &corev1.Pod{}
			if err := intercepted.Get(context.Background(), client.ObjectKeyFromObject(p), fresh); err != nil {
				t.Fatal(err)
			}
			original := fresh.DeepCopy()
			fresh.Annotations = copyAnnotations(fresh.Annotations)
			fresh.Annotations[webhook.ConfigAnnotation] = "forged"
			if err := intercepted.Patch(context.Background(), fresh, client.MergeFrom(original)); err == nil || !strings.Contains(err.Error(), "client config is immutable") {
				t.Fatalf("immutable client config accepted: %v", err)
			}
		})
	}
}
