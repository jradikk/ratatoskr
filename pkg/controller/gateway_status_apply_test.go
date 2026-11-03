package controller

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type conflictGatewayClient struct {
	client.Client
	attempts int
	before   func(context.Context, client.Object) error
}

func (c *conflictGatewayClient) Status() client.SubResourceWriter {
	return conflictGatewayWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

type conflictGatewayWriter struct {
	client.SubResourceWriter
	parent *conflictGatewayClient
}

func (w conflictGatewayWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	w.parent.attempts++
	if w.parent.attempts == 1 {
		if w.parent.before != nil {
			if err := w.parent.before(ctx, obj); err != nil {
				return err
			}
		}
		return apierrors.NewConflict(api.SchemeGroupVersion.WithResource("egressgateways").GroupResource(), obj.GetName(), errors.New("test-only optimistic lock"))
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestGatewayStatusRetriesFreshResourceVersionAndPreservesOtherConditions(t *testing.T) {
	r, gw := fixture(t)
	underlying := r.Client
	wrapper := &conflictGatewayClient{Client: underlying}
	wrapper.before = func(ctx context.Context, _ client.Object) error {
		var latest api.EgressGateway
		if err := underlying.Get(ctx, client.ObjectKeyFromObject(gw), &latest); err != nil {
			return err
		}
		meta.SetStatusCondition(&latest.Status.Conditions, metav1.Condition{Type: "Independent", Status: metav1.ConditionTrue,
			Reason: "OtherController", Message: "unrelated status", ObservedGeneration: latest.Generation})
		return underlying.Status().Update(ctx, &latest)
	}
	r.Client = wrapper
	gw = getGatewayForFailureEvent(t, r, gw.Name)
	if err := r.status(context.Background(), gw, false, "GatewayHealth", "waiting"); err != nil {
		t.Fatal(err)
	}
	if wrapper.attempts != 2 {
		t.Fatalf("expected one optimistic-lock retry, got %d", wrapper.attempts)
	}
	persisted := getGatewayForFailureEvent(t, r, gw.Name)
	if got := meta.FindStatusCondition(persisted.Status.Conditions, "Independent"); got == nil || got.Reason != "OtherController" {
		t.Fatalf("other condition overwritten: %+v", got)
	}
	if gw.ResourceVersion != persisted.ResourceVersion || gw.UID != persisted.UID || !reflect.DeepEqual(gw.Status, persisted.Status) {
		t.Fatal("caller did not receive persisted current Gateway")
	}
	before := persisted.DeepCopy()
	if err := r.status(context.Background(), persisted, false, "GatewayHealth", "waiting"); err != nil {
		t.Fatal(err)
	}
	if wrapper.attempts != 2 || persisted.ResourceVersion != before.ResourceVersion || !reflect.DeepEqual(persisted.Status, before.Status) {
		t.Fatal("no-op status changed resourceVersion or condition transition time")
	}
}

func TestGatewayStatusRejectsChangedUIDGenerationOrSpec(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*api.EgressGateway)
	}{
		{"uid", func(g *api.EgressGateway) { g.UID = types.UID("recreated") }},
		{"generation", func(g *api.EgressGateway) { g.Generation++ }},
		{"spec", func(g *api.EgressGateway) { g.Spec.FailMode = "closed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, gw := fixture(t)
			current := getGatewayForFailureEvent(t, r, gw.Name)
			tc.mutate(current)
			if err := r.Update(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			original := gw.DeepCopy()
			if err := r.status(context.Background(), original, false, "GatewayHealth", "waiting"); !apierrors.IsConflict(err) {
				t.Fatalf("stale Gateway status not refused: %v", err)
			}
			persisted := getGatewayForFailureEvent(t, r, gw.Name)
			if meta.FindStatusCondition(persisted.Status.Conditions, "Ready") != nil {
				t.Fatal("stale status overwritten after identity change")
			}
		})
	}
}

func TestGatewayApplyAdviceSafeFixedResourceAndAPIErrorClasses(t *testing.T) {
	const private = "PRIVATE-API-URL-token"
	secret := errors.New(private)
	kinds := []client.Object{&corev1.ConfigMap{}, &corev1.Service{}, &appsv1.Deployment{}}
	for _, obj := range kinds {
		for _, tc := range []struct {
			operation string
			cause     error
			want      string
		}{
			{"read", apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "private", secret), "ReadDenied"},
			{"read", secret, "ReadFailed"},
			{"create", apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "private", secret), "Conflict"},
			{"update", apierrors.NewBadRequest(private), "Invalid"},
			{"update", secret, "WriteFailed"},
		} {
			wrapped := classifyApplyError(obj, tc.operation, tc.cause)
			if !errors.Is(wrapped, tc.cause) {
				t.Fatal("internal API error cause lost")
			}
			code, text := applyAdvice(wrapped)
			if !strings.HasSuffix(code, tc.want) || !strings.Contains(text, applyResource(obj)) ||
				strings.Contains(code+text+wrapped.Error(), private) {
				t.Fatalf("unsafe or vague apply advice: %q %q", code, text)
			}
		}
	}
	code, text := applyAdvice(&applyFailure{resource: "Secret=" + private, category: "Invalid", cause: secret})
	if code != "resourceInvalid" || strings.Contains(text, private) {
		t.Fatal("untrusted resource name leaked")
	}
	code, text = applyAdvice(secret)
	if code != "Unknown" || strings.Contains(text, private) {
		t.Fatal("raw API error leaked")
	}
}

func TestGatewayApplyStatusEventLogAndOwnerConflictRemainSafe(t *testing.T) {
	r, gw := fixture(t)
	recorder := events.NewFakeRecorder(4)
	r.Recorder = recorder
	var output bytes.Buffer
	ctx := log.IntoContext(context.Background(), logr.New(&safeLogSink{output: &output}))
	private := errors.New("PRIVATE-API-URL-token")
	owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace}}
	if err := r.Create(ctx, owner); err != nil {
		t.Fatal(err)
	}
	cause := r.apply(ctx, gw, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace}})
	var typed *applyFailure
	if !errors.As(cause, &typed) || typed.category != "OwnershipConflict" {
		t.Fatalf("foreign owner not refused: %v", cause)
	}
	if _, err := r.failure(ctx, gw, "ApplyFailed", classifyApplyError(owner, "update", private)); err != nil {
		t.Fatal(err)
	}
	stored := getGatewayForFailureEvent(t, r, gw.Name)
	for _, kind := range []string{"Ready", "ApplyFailed"} {
		c := meta.FindStatusCondition(stored.Status.Conditions, kind)
		if c == nil || !strings.Contains(c.Message, "ConfigMap") || strings.Contains(c.Message, "PRIVATE") {
			t.Fatalf("unsafe actionable condition %s: %+v", kind, c)
		}
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "ConfigMap") || strings.Contains(event, "PRIVATE") {
			t.Fatalf("unsafe event: %q", event)
		}
	default:
		t.Fatal("missing apply failure warning")
	}
	if !strings.Contains(output.String(), "ConfigMapWriteFailed") || strings.Contains(output.String(), "PRIVATE") {
		t.Fatalf("unsafe log: %s", output.String())
	}
}
