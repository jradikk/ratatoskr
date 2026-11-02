package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type countingDeploymentClient struct {
	client.Client
	updates int
	reads   int
	create  int
	forced  error
	missing bool
}

func (c *countingDeploymentClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*appsv1.Deployment); ok {
		c.updates++
	}
	return c.Client.Update(ctx, obj, opts...)
}
func (c *countingDeploymentClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*appsv1.Deployment); ok {
		c.reads++
		if c.forced != nil {
			return c.forced
		}
		if c.missing {
			return apierrors.NewNotFound(schema.GroupResource{Resource: "deployments"}, key.Name)
		}
	}
	return c.Client.Get(ctx, key, obj, opts...)
}
func (c *countingDeploymentClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*appsv1.Deployment); ok {
		c.create++
	}
	return c.Client.Create(ctx, obj, opts...)
}

func TestDefaultedOwnedGatewayDeploymentDoesNotUpdateOrRecreate(t *testing.T) {
	r, gw := fixture(t)
	gw.Status.GatewayID = 17
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var desired *appsv1.Deployment
	for _, obj := range objects {
		if d, ok := obj.(*appsv1.Deployment); ok {
			desired = d
		}
	}
	if desired == nil {
		t.Fatal("missing desired Gateway Deployment")
	}
	live := desired.DeepCopy()
	live.UID = types.UID("unchanged-gateway-deployment")
	live.Spec.RevisionHistoryLimit = new(int32)
	*live.Spec.RevisionHistoryLimit = 10
	live.Spec.ProgressDeadlineSeconds = new(int32)
	*live.Spec.ProgressDeadlineSeconds = 600
	live.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
	live.Spec.Template.Spec.SchedulerName = corev1.DefaultSchedulerName
	live.Spec.Template.Spec.TerminationGracePeriodSeconds = new(int64)
	*live.Spec.Template.Spec.TerminationGracePeriodSeconds = 30
	live.Spec.Template.Spec.EnableServiceLinks = new(bool)
	*live.Spec.Template.Spec.EnableServiceLinks = true
	live.Spec.Template.Spec.ServiceAccountName = "default"
	for i := range live.Spec.Template.Spec.Containers {
		c := &live.Spec.Template.Spec.Containers[i]
		c.TerminationMessagePath = "/dev/termination-log"
		c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		if c.ReadinessProbe != nil {
			c.ReadinessProbe.TimeoutSeconds = 1
			if c.ReadinessProbe.PeriodSeconds == 0 {
				c.ReadinessProbe.PeriodSeconds = 10
			}
			c.ReadinessProbe.SuccessThreshold = 1
			c.ReadinessProbe.FailureThreshold = 3
		}
	}
	if err := r.Create(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	wrap := &countingDeploymentClient{Client: r.Client}
	r.Client = wrap
	before := &appsv1.Deployment{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(live), before); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), gw, desired.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if wrap.updates != 0 {
		t.Fatal("default-only Deployment drift triggered update")
	}
	after := &appsv1.Deployment{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(live), after); err != nil {
		t.Fatal(err)
	}
	if after.UID != before.UID || after.ResourceVersion != before.ResourceVersion || !reflect.DeepEqual(after.Spec, before.Spec) {
		t.Fatal("default-only drift changed Deployment, Pod template, or UID")
	}
	image := desired.DeepCopy()
	image.Spec.Template.Spec.Containers[0].Image = "gateway:new-image"
	if err := r.apply(context.Background(), gw, image); err != nil {
		t.Fatal(err)
	}
	if wrap.updates != 1 {
		t.Fatal("intended image upgrade did not update Deployment")
	}
	newTemplate := image.DeepCopy()
	unprivileged := false
	newTemplate.Spec.Template.Spec.Containers[0].SecurityContext.Privileged = &unprivileged
	if err := r.apply(context.Background(), gw, newTemplate); err != nil {
		t.Fatal(err)
	}
	if wrap.updates != 2 {
		t.Fatal("changed gateway privilege ignored")
	}
	// Probe destination is a security-relevant rendered field, not a server
	// default; it must still update.
	probe := newTemplate.DeepCopy()
	probe.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Path = "/wrong"
	if err := r.apply(context.Background(), gw, probe); err != nil {
		t.Fatal(err)
	}
	if wrap.updates != 3 {
		t.Fatal("changed readiness path ignored")
	}
}

func TestTransientGatewayApplyRaceKeepsOwnedDeployment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		missing bool
	}{
		{"conflict", apierrors.NewConflict(schema.GroupResource{Resource: "deployments"}, "edge", errors.New("private")), false},
		{"already exists after stale cache", apierrors.NewAlreadyExists(schema.GroupResource{Resource: "deployments"}, "edge"), true},
		{"forbidden is not transient", apierrors.NewForbidden(schema.GroupResource{Resource: "deployments"}, "edge", errors.New("private")), false},
		{"arbitrary transport error is not transient", errors.New("private transport"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, gw := fixture(t)
			gw.Status.GatewayID = 17
			objs, err := r.render(gw, nil)
			if err != nil {
				t.Fatal(err)
			}
			var dep *appsv1.Deployment
			for _, obj := range objs {
				if d, ok := obj.(*appsv1.Deployment); ok {
					dep = d
				}
			}
			if dep == nil {
				t.Fatal("missing Deployment")
			}
			if err := r.Create(context.Background(), dep); err != nil {
				t.Fatal(err)
			}
			wrap := &countingDeploymentClient{Client: r.Client, forced: tc.err, missing: tc.missing}
			if tc.missing {
				wrap.forced = nil
			}
			r.Client = wrap
			desired := dep.DeepCopy()
			desired.ResourceVersion = "" // freshly rendered object, not the API-mutated test instance
			desired.UID = ""
			err = r.apply(context.Background(), gw, desired)
			var failure *applyFailure
			if !errors.As(err, &failure) {
				t.Fatalf("typed failure absent: %v", err)
			}
			if failure.transient != (tc.name == "conflict" || tc.missing) {
				t.Fatalf("wrong transient classification: category=%s cause=%v already=%t", failure.category, failure.cause, apierrors.IsAlreadyExists(failure.cause))
			}
			if !tc.missing && wrap.create != 0 {
				t.Fatal("non-NotFound read attempted CREATE")
			}
			if tc.missing && wrap.create != 1 {
				t.Fatal("stale NotFound did not attempt exact one CREATE")
			}
			stored := &appsv1.Deployment{}
			if err := wrap.Client.Get(context.Background(), client.ObjectKeyFromObject(dep), stored); err != nil || stored.UID != dep.UID {
				t.Fatalf("transient apply deleted owned deployment: %v", err)
			}
		})
	}
}

func TestGatewayReconcileTransientApplyDoesNotCallBlock(t *testing.T) {
	r, gw := fixture(t)
	// Render/apply prerequisites are intentionally unchanged. The unit above
	// exercises the exact stale-read AlreadyExists path and classification;
	// here verify full reconciliation leaves an owned Deployment intact on
	// an API-conflict while retaining the Gateway's existing status.
	ctx := context.Background()
	if err := r.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{PodCIDR: "10.42.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{}
	if err := r.Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	fresh := &api.EgressGateway{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(gw), fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Status.GatewayID = 17
	if err := r.Status().Update(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	objs, err := r.render(fresh, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range objs {
		if obj.GetName() == fresh.Name && obj.GetNamespace() == fresh.Namespace {
			if err := r.Create(ctx, obj); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Fatal(err)
			}
		}
	}
	wrap := &countingDeploymentClient{Client: r.Client, forced: apierrors.NewConflict(schema.GroupResource{Resource: "deployments"}, "edge", errors.New("private"))}
	r.Client = wrap
	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("transient conflict not scheduled for retry")
	}
	stored := &appsv1.Deployment{}
	if err := wrap.Client.Get(ctx, client.ObjectKeyFromObject(fresh), stored); err != nil {
		t.Fatalf("transient conflict deleted Deployment: %v", err)
	}
}
