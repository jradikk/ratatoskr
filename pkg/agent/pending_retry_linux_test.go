//go:build linux

package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type countingPendingClient struct {
	client.WithWatch
	counts chan int
	total  int
}

func (c *countingPendingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	err := c.WithWatch.List(ctx, list, opts...)
	if _, ok := list.(*corev1.PodList); ok {
		c.total++
		select {
		case c.counts <- c.total:
		default:
		}
	}
	return err
}
func (c *countingPendingClient) Watch(context.Context, client.ObjectList, ...client.ListOption) (watch.Interface, error) {
	return watch.NewRaceFreeFake(), nil
}
func TestPendingOnlyFastResyncStopsWhenSelectedPodNoLongerPending(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if verifiedOwn.Load() != nil {
		t.Skip("existing own namespace anchor")
	}
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(own.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	verifiedOwn.Store(&ownNamespaceAnchor{fd: own, stat: st})
	defer verifiedOwn.Store(nil)
	ownPod, id := validOwnPod()
	workload := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "selected", Namespace: "apps", UID: "selected-uid", Labels: map[string]string{GatewayLabel: "vpn"}}, Spec: corev1.PodSpec{NodeName: id.Node}}
	scheme := k8sruntime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	inner := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ownPod, workload).Build()
	c := &countingPendingClient{WithWatch: inner, counts: make(chan int, 16)}
	r := &Reconciler{Client: c, WatchClient: c, Own: id, Node: id.Node, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	for want := 1; want <= 2; want++ {
		select {
		case n := <-c.counts:
			if n != want {
				t.Fatalf("unexpected list count %d", n)
			}
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("selected Pending workload waited for 30s periodic resync")
		}
	}
	current := &corev1.Pod{}
	if err = c.Get(context.Background(), client.ObjectKeyFromObject(workload), current); err != nil {
		t.Fatal(err)
	}
	current.Labels = nil
	if err = c.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	verified := &corev1.Pod{}
	if err = c.Get(context.Background(), client.ObjectKeyFromObject(workload), verified); err != nil {
		t.Fatal(err)
	}
	if verified.Labels[GatewayLabel] != "" {
		t.Fatal("opt-out did not persist in fake API")
	}
	// Give one in-flight ticker callback time to finish. Afterwards the
	// selected-pending flag must remain false and the node must stay Ready.
	select {
	case <-time.After(600 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal("pending waiter canceled")
	}
	if r.pendingStartup.Load() {
		t.Fatal("opt-out retained selected-pending flag")
	}
	// A queued watch/sync may have produced LISTs before the bit cleared;
	// only verify no active pending flag and bounded cancellation here.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("agent Run did not stop")
	}
}
