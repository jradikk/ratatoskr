//go:build linux

package agent

import (
	"context"
	"os"
	goruntime "runtime"
	"testing"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func validOwnPod() (*corev1.Pod, OwnPod) {
	id := OwnPod{Namespace: "operator", Name: "agent-1", UID: "agent-uid", Node: "node-1"}
	fields := []struct{ name, path string }{{"POD_NAMESPACE", "metadata.namespace"}, {"POD_NAME", "metadata.name"}, {"POD_UID", "metadata.uid"}, {"NODE_NAME", "spec.nodeName"}}
	env := make([]corev1.EnvVar, 0, len(fields))
	for _, field := range fields {
		env = append(env, corev1.EnvVar{Name: field.name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: field.path}}})
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: id.Namespace, Name: id.Name, UID: types.UID(id.UID)}, Spec: corev1.PodSpec{NodeName: id.Node, HostNetwork: false, HostPID: true, ServiceAccountName: "ratatoskr-agent", Containers: []corev1.Container{{Name: "agent", Env: env}}}}
	return pod, id
}
func TestTrustedOwnPodIdentity(t *testing.T) {
	p, id := validOwnPod()
	if err := validateOwnPod(p, id); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod, *OwnPod)
	}{
		{"forged UID", func(_ *corev1.Pod, id *OwnPod) { id.UID = "fake" }},
		{"missing UID", func(_ *corev1.Pod, id *OwnPod) { id.UID = "" }},
		{"node mismatch", func(_ *corev1.Pod, id *OwnPod) { id.Node = "other" }},
		{"host network", func(p *corev1.Pod, _ *OwnPod) { p.Spec.HostNetwork = true }},
		{"nonhost PID", func(p *corev1.Pod, _ *OwnPod) { p.Spec.HostPID = false }},
		{"service account mismatch", func(p *corev1.Pod, _ *OwnPod) { p.Spec.ServiceAccountName = "default" }},
		{"deleting", func(p *corev1.Pod, _ *OwnPod) { now := metav1.Now(); p.DeletionTimestamp = &now }},
		{"forged env", func(p *corev1.Pod, _ *OwnPod) {
			p.Spec.Containers[0].Env[0].ValueFrom = nil
			p.Spec.Containers[0].Env[0].Value = "forged"
		}},
		{"wrong fieldRef", func(p *corev1.Pod, _ *OwnPod) {
			p.Spec.Containers[0].Env[1].ValueFrom.FieldRef.FieldPath = "metadata.uid"
		}},
		{"duplicate env", func(p *corev1.Pod, _ *OwnPod) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, p.Spec.Containers[0].Env[0])
		}},
		{"missing fieldRef", func(p *corev1.Pod, _ *OwnPod) { p.Spec.Containers[0].Env = p.Spec.Containers[0].Env[1:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, id := validOwnPod()
			tc.change(p, &id)
			if err := validateOwnPod(p, id); err == nil {
				t.Fatal("untrusted own Pod accepted")
			}
		})
	}
}
func TestUncachedOwnPodRecheck(t *testing.T) {
	p, id := validOwnPod()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	k := fake.NewClientBuilder().WithScheme(scheme).WithObjects(p).Build()
	r := &Reconciler{Client: k, Own: id}
	if err := r.VerifyOwnPod(context.Background()); err != nil {
		t.Fatal(err)
	}
	id.UID = "stale"
	r.Own = id
	if err := r.VerifyOwnPod(context.Background()); err == nil {
		t.Fatal("stale own UID accepted")
	}
	r.Client = nil
	if err := r.VerifyOwnPod(context.Background()); err == nil {
		t.Fatal("API unavailable accepted")
	}
}
func TestOwnNamespaceAnchorRejectsOwnAndStaleFD(t *testing.T) {
	if verifiedOwn.Load() != nil {
		t.Skip("another test established process anchor")
	}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	ordinary, err := os.CreateTemp(t.TempDir(), "not-a-network-namespace")
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	if _, err := validateOwnAnchor(ordinary); err == nil {
		t.Fatal("regular file accepted as agent namespace anchor")
	}
	if err := rejectOwn(own); err == nil {
		t.Fatal("unbootstrapped namespace accepted")
	}
	if err := checkThreadOwn(); err == nil {
		t.Fatal("unbootstrapped thread accepted")
	}
	anchor, err := validateOwnAnchor(own)
	if err != nil {
		t.Fatal(err)
	}
	verifiedOwn.Store(anchor)
	defer verifiedOwn.Store(nil)
	if err := checkThreadOwn(); err != nil {
		t.Fatal(err)
	}
	if err := rejectOwn(own); err == nil {
		t.Fatal("agent netns accepted as target")
	}
	verifiedOwn.Store(&ownNamespaceAnchor{fd: own, stat: unix.Stat_t{Dev: anchor.stat.Dev, Ino: anchor.stat.Ino + 1}})
	if err := checkThreadOwn(); err == nil {
		t.Fatal("stale pinned agent namespace accepted")
	}
	verifiedOwn.Store(anchor)
}
