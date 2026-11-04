//go:build linux

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type countQuarantinePatch struct {
	client.Client
	count int
}

func (c *countQuarantinePatch) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.count++
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func TestPersistFirstSafeQuarantineReasonWithoutChurn(t *testing.T) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "ns", UID: types.UID("pod-uid"), Annotations: map[string]string{ReadyAnnotation: "true"}}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(p).Build()
	counting := &countQuarantinePatch{Client: base}
	r := &Reconciler{Client: counting}
	first, err := r.recordQuarantine(context.Background(), p, quarantineNamespaceRead)
	if first || err != nil || counting.count != 1 {
		t.Fatalf("first quarantine not recorded: %t %v %d", first, err, counting.count)
	}
	stale := p.DeepCopy()
	stale.Annotations[QuarantineReasonAnnotation] = ""
	already, err := r.recordQuarantine(context.Background(), stale, quarantineGatewayRead)
	if !already || err != nil || counting.count != 1 {
		t.Fatalf("repeated quarantine churned Pod: %t %v %d", already, err, counting.count)
	}
	current := &corev1.Pod{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(p), current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[QuarantineReasonAnnotation] != quarantineNamespaceRead || current.Annotations[ReadyAnnotation] != "pending" {
		t.Fatalf("first reason not retained: %+v", current.Annotations)
	}
	current.UID = "replaced"
	if _, err := r.recordQuarantine(context.Background(), current, quarantinePolicyRead); err == nil {
		t.Fatal("replaced Pod reason overwritten")
	}
}

func TestQuarantineReasonNeverEchoesPrivateErrorAndDomainStages(t *testing.T) {
	for _, reason := range []string{quarantineNamespaceRead, quarantineGatewayRead, quarantinePolicyRead, quarantineAuthorization, quarantineDomainRedirect, quarantineDomainPersistence, quarantineDomainRouting, quarantineDomainRuntime, "PRIVATE-TOKEN"} {
		err := quarantineError(reason)
		if !strings.Contains(err.Error(), "recreate Pod") || strings.Contains(err.Error(), "PRIVATE-TOKEN") {
			t.Fatalf("unsafe quarantine reason: %v", err)
		}
	}
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{errors.New("DNS interception missing"), quarantineDomainRedirect},
		{errors.New("domain policy or resolver changed; rollout required"), quarantineDomainPolicy},
		{errors.New("owned DNS server stopped"), quarantineDomainListener},
		{errors.New("PRIVATE-TOKEN dns route failed"), quarantineDomainRuntime},
	} {
		if got := reasonForDomainCause(tc.cause); got != tc.want {
			t.Fatalf("cause class %s want %s", got, tc.want)
		}
	}
}
