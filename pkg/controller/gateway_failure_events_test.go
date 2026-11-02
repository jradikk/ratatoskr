package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func getGatewayForFailureEvent(t *testing.T, r *GatewayReconciler, name string) *api.EgressGateway {
	t.Helper()
	gw := &api.EgressGateway{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: name}, gw); err != nil {
		t.Fatal(err)
	}
	return gw
}

func nextGatewayWarning(t *testing.T, recorder *events.FakeRecorder, reason string) {
	t.Helper()
	select {
	case text := <-recorder.Events:
		if !strings.HasPrefix(text, "Warning "+reason+" ") || strings.Contains(text, "PRIVATE-PROFILE") {
			t.Fatalf("unexpected or private warning Event: %q", text)
		}
	default:
		t.Fatalf("missing Warning Event %s", reason)
	}
}
func noGatewayWarning(t *testing.T, recorder *events.FakeRecorder) {
	t.Helper()
	select {
	case text := <-recorder.Events:
		t.Fatalf("unexpected duplicate warning Event: %q", text)
	default:
	}
}

func TestGatewayFailureEventTransitionAndSafeStatus(t *testing.T) {
	r, gw := fixture(t)
	recorder := events.NewFakeRecorder(16)
	r.Recorder = recorder
	var output bytes.Buffer
	ctx := log.IntoContext(context.Background(), logr.New(&safeLogSink{output: &output}))
	private := errors.New("PRIVATE-PROFILE token/cert 10.42.1.8")
	fail := func(reason string) {
		t.Helper()
		gw = getGatewayForFailureEvent(t, r, gw.Name)
		if _, err := r.failure(ctx, gw, reason, private); err != nil {
			t.Fatal(err)
		}
		gw = getGatewayForFailureEvent(t, r, gw.Name)
		ready := meta.FindStatusCondition(gw.Status.Conditions, "Ready")
		if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != reason ||
			strings.Contains(ready.Message, "PRIVATE-PROFILE") {
			t.Fatalf("unsafe Ready failure condition: %+v", ready)
		}
		condition := meta.FindStatusCondition(gw.Status.Conditions, reason)
		if condition == nil || condition.Status != metav1.ConditionTrue ||
			strings.Contains(condition.Message, "PRIVATE-PROFILE") {
			t.Fatalf("unsafe failure condition: %+v", condition)
		}
	}
	fail("SecretUnavailable")
	nextGatewayWarning(t, recorder, "SecretUnavailable")
	fail("SecretUnavailable")
	noGatewayWarning(t, recorder)
	fail("ApplyFailed")
	nextGatewayWarning(t, recorder, "ApplyFailed")
	// Ready recovery, then the same reason, must be a new failure transition.
	gw = getGatewayForFailureEvent(t, r, gw.Name)
	if err := r.status(ctx, gw, true, "Available", "gateway ready"); err != nil {
		t.Fatal(err)
	}
	fail("ApplyFailed")
	nextGatewayWarning(t, recorder, "ApplyFailed")
	if strings.Contains(output.String(), "PRIVATE-PROFILE") {
		t.Fatalf("private error appeared in controller log: %s", output.String())
	}
}

func TestGatewayFailureEventWaitsForPersistedStatus(t *testing.T) {
	r, gw := fixture(t)
	recorder := events.NewFakeRecorder(4)
	r.Recorder = recorder
	// A missing Gateway makes the status write fail. No Event may claim a
	// transition that was never successfully persisted.
	if err := r.Delete(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	if _, err := r.failure(context.Background(), gw, "SecretUnavailable", errors.New("PRIVATE-PROFILE")); err == nil {
		t.Fatal("missing Gateway unexpectedly accepted status update")
	}
	noGatewayWarning(t, recorder)
}

func TestGatewayFailureReasonUnknownSanitizedAndNilRecorder(t *testing.T) {
	r, gw := fixture(t)
	gw = getGatewayForFailureEvent(t, r, gw.Name)
	if _, err := r.failure(context.Background(), gw, "PRIVATE-PROFILE", errors.New("PRIVATE-PROFILE")); err != nil {
		t.Fatal(err)
	}
	current := getGatewayForFailureEvent(t, r, gw.Name)
	for _, condition := range current.Status.Conditions {
		if strings.Contains(condition.Reason, "PRIVATE-PROFILE") || strings.Contains(condition.Message, "PRIVATE-PROFILE") {
			t.Fatalf("untrusted failure leaked to Gateway condition: %+v", condition)
		}
	}
	if ready := meta.FindStatusCondition(current.Status.Conditions, "Ready"); ready == nil || ready.Reason != "ReconcileFailed" {
		t.Fatalf("unknown reason not normalized: %+v", ready)
	}
}

func TestGatewayPendingHealthDoesNotEmitRepeatedWarning(t *testing.T) {
	r, gw := fixture(t)
	recorder := events.NewFakeRecorder(16)
	r.Recorder = recorder
	// A non-failure status update must not pass through failure() or publish a Warning.
	if err := r.status(context.Background(), gw, false, "NoHealthyEndpoints", "waiting for healthy gateway"); err != nil {
		t.Fatal(err)
	}
	gw = getGatewayForFailureEvent(t, r, gw.Name)
	if err := r.status(context.Background(), gw, false, "NoHealthyEndpoints", "waiting for healthy gateway"); err != nil {
		t.Fatal(err)
	}
	noGatewayWarning(t, recorder)
}

// safeLogSink is used only to prove the controller's structured log omits the
// private failure; its simple serializer never handles Pod/Secret objects.
type safeLogSink struct{ output *bytes.Buffer }

func (s *safeLogSink) Init(logr.RuntimeInfo) {}
func (s *safeLogSink) Enabled(int) bool      { return true }
func (s *safeLogSink) Info(_ int, msg string, keysAndValues ...any) {
	_, _ = s.output.WriteString(msg)
	for _, value := range keysAndValues {
		_, _ = s.output.WriteString(" ")
		_, _ = fmt.Fprint(s.output, value)
	}
}
func (s *safeLogSink) Error(err error, msg string, keysAndValues ...any) {
	_, _ = s.output.WriteString(msg + " " + err.Error())
}
func (s *safeLogSink) WithValues(...any) logr.LogSink { return s }
func (s *safeLogSink) WithName(string) logr.LogSink   { return s }
