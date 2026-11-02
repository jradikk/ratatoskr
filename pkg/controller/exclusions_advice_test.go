package controller

import (
	"bytes"
	"context"
	stdErrors "errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestExclusionAdviceFixedCategoriesNeverEchoCause(t *testing.T) {
	const secret = "SECRET-TOKEN-URL-private.example.invalid"
	private := stdErrors.New(secret)
	cases := []struct {
		code, want string
	}{
		{"PodCIDRsMissing", "exclusions.podCIDRs"},
		{"NodePodCIDRMissing", "Node.spec.podCIDRs"},
		{"ServiceCIDRsMissing", "exclusions.serviceCIDRs"},
		{"ConfiguredCIDRInvalid", "exclusions.extraCIDRs"},
		{"NodeCIDRInvalid", "Node.status.addresses"},
		{"ServiceCIDRInvalid", "ServiceCIDR data"},
		{"EndpointAddressInvalid", "EndpointSlice"},
		{"ExclusionsTooMany", "reduce"},
		{"NodesReadDenied", "nodes list"},
		{"PodsReadDenied", "pods list"},
		{"ServiceReadDenied", "services get"},
		{"ServiceCIDRsReadDenied", "servicecidrs list"},
		{"EndpointSlicesReadDenied", "endpointslices list"},
		{"NodesReadFailed", "Nodes"},
		{"PodsReadFailed", "Gateway Pods"},
		{"ServiceReadFailed", "Services"},
		{"ServiceCIDRsReadFailed", "ServiceCIDRs"},
		{"EndpointSlicesReadFailed", "EndpointSlices"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			wrapped := exclusionError(tc.code, private)
			if !stdErrors.Is(wrapped, private) {
				t.Fatal("internal cause lost")
			}
			code, message := exclusionAdvice(wrapped)
			if code != tc.code || !strings.Contains(message, tc.want) || strings.Contains(message, secret) || strings.Contains(wrapped.Error(), secret) {
				t.Fatalf("unsafe or unactionable advice: %q %q", code, message)
			}
		})
	}
	for _, cause := range []error{private, exclusionError(secret, private)} {
		code, message := exclusionAdvice(cause)
		if code != "Unknown" || strings.Contains(message, secret) || !strings.Contains(message, "check controller access") {
			t.Fatal("unknown exclusion error leaked untrusted text")
		}
	}
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "private", private)
	code, _ := exclusionAdvice(exclusionReadError("Nodes", forbidden))
	if code != "NodesReadDenied" {
		t.Fatal("forbidden Nodes LIST did not name permission category")
	}
	code, _ = exclusionAdvice(exclusionReadError("Nodes", private))
	if code != "NodesReadFailed" {
		t.Fatal("transient Nodes LIST confused with permission denial")
	}
}

func TestCollectedExclusionCausesSelectSafeRemediation(t *testing.T) {
	for _, tc := range []struct {
		name, configure string
		want, advice    string
	}{
		{"unknown Pod CIDRs", "pod-missing", "PodCIDRsMissing", "exclusions.podCIDRs"},
		{"node without Pod CIDR", "node-missing", "NodePodCIDRMissing", "Node.spec.podCIDRs"},
		{"unknown Service CIDRs", "service-missing", "ServiceCIDRsMissing", "exclusions.serviceCIDRs"},
		{"invalid configured CIDR", "invalid", "ConfiguredCIDRInvalid", "exclusions.extraCIDRs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, gw := fixture(t)
			switch tc.configure {
			case "pod-missing":
				r.Options.PodCIDRs = ""
			case "node-missing":
				r.Options.PodCIDRs = ""
				if err := r.Create(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}); err != nil {
					t.Fatal(err)
				}
			case "service-missing":
				r.Options.ServiceCIDRs = ""
			case "invalid":
				r.Options.ExtraCIDRs = "SECRET-TOKEN-URL-private.example.invalid"
			}
			_, _, err := r.collectExclusions(context.Background(), gw)
			code, text := exclusionAdvice(err)
			if code != tc.want || !strings.Contains(text, tc.advice) || strings.Contains(text, "SECRET-TOKEN-URL") {
				t.Fatalf("unexpected collected category %q (%s)", code, text)
			}
		})
	}
}

func TestExclusionStatusEventAndLogAreActionableAndPrivate(t *testing.T) {
	r, gw := fixture(t)
	recorder := events.NewFakeRecorder(8)
	r.Recorder = recorder
	var output bytes.Buffer
	ctx := log.IntoContext(context.Background(), logr.New(&safeLogSink{output: &output}))
	const secret = "SECRET-TOKEN-URL-private.example.invalid"
	fail := func(code, expect string) {
		t.Helper()
		current := getGatewayForFailureEvent(t, r, gw.Name)
		if _, err := r.failure(ctx, current, "ExclusionDiscoveryFailed", exclusionError(code, stdErrors.New(secret))); err != nil {
			t.Fatal(err)
		}
		current = getGatewayForFailureEvent(t, r, gw.Name)
		for _, kind := range []string{"Ready", "ExclusionDiscoveryFailed"} {
			c := meta.FindStatusCondition(current.Status.Conditions, kind)
			if c == nil || kind == "Ready" && c.Status != metav1.ConditionFalse ||
				kind == "ExclusionDiscoveryFailed" && c.Status != metav1.ConditionTrue ||
				c.Reason != "ExclusionDiscoveryFailed" || !strings.Contains(c.Message, expect) ||
				strings.Contains(c.Message, secret) {
				t.Fatalf("failure condition %s omitted safe advice: %+v", kind, c)
			}
		}
		select {
		case event := <-recorder.Events:
			if !strings.Contains(event, expect) || strings.Contains(event, secret) {
				t.Fatalf("unsafe Event: %q", event)
			}
		default:
			t.Fatal("missing actionable exclusion Event")
		}
	}
	fail("ServiceCIDRsMissing", "exclusions.serviceCIDRs")
	// Identical reason/cause only updates status, not repeated Events.
	current := getGatewayForFailureEvent(t, r, gw.Name)
	if _, err := r.failure(ctx, current, "ExclusionDiscoveryFailed", exclusionError("ServiceCIDRsMissing", nil)); err != nil {
		t.Fatal(err)
	}
	noGatewayWarning(t, recorder)
	if !strings.Contains(output.String(), "ServiceCIDRsMissing") || strings.Contains(output.String(), secret) {
		t.Fatalf("log omitted fixed category or leaked cause: %s", output.String())
	}
	// A changed category emits one new safe Event despite a stable Ready reason.
	current = getGatewayForFailureEvent(t, r, gw.Name)
	if _, err := r.failure(ctx, current, "ExclusionDiscoveryFailed", exclusionError("NodesReadDenied", nil)); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(getGatewayForFailureEvent(t, r, gw.Name).Status.Conditions, "Ready"); !strings.Contains(got.Message, "nodes list") {
		t.Fatalf("changed exclusion cause omitted remediation: %+v", got)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "nodes list") || strings.Contains(event, secret) {
			t.Fatalf("changed exclusion category Event not safe: %q", event)
		}
	default:
		t.Fatal("missing changed exclusion category Event")
	}
	noGatewayWarning(t, recorder)
}
