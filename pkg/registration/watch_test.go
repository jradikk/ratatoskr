package registration

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	kt "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The watch fixture uses an already-registered synthetic peer and explicit
// watch streams; neither JWTs nor private keys pass through the watch.
func watchFixture(t *testing.T) (*Server, *peers, *corev1.Pod, context.CancelFunc, <-chan error, <-chan *watch.RaceFreeFakeWatcher) {
	t.Helper()
	s, p, pod, _, _, _ := fixture(t)
	if code := send(s); code != 201 {
		t.Fatalf("register peer: %d", code)
	}
	streams := make(chan *watch.RaceFreeFakeWatcher, 4)
	s.Kubernetes.(*kt.Clientset).PrependWatchReactor("pods", func(ktesting.Action) (bool, watch.Interface, error) {
		w := watch.NewRaceFreeFake()
		streams <- w
		return true, w, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.WatchPods(ctx) }()
	return s, p, pod, cancel, done, streams
}
func nextStream(t *testing.T, ch <-chan *watch.RaceFreeFakeWatcher) *watch.RaceFreeFakeWatcher {
	t.Helper()
	select {
	case w := <-ch:
		return w
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not start")
		return nil
	}
}
func waitRemoved(t *testing.T, s *Server, p *peers, count int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(time.Millisecond * 10)
	defer tick.Stop()
	for {
		s.mu.Lock()
		got := p.removed
		s.mu.Unlock()
		if got == count {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("removed=%d, want %d", got, count)
		case <-tick.C:
		}
	}
}
func finishWatch(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch ignored cancellation")
	}
}
func TestWatchDeletesAndReplacementUID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		event    watch.EventType
		uid      string
		deleting bool
		want     int
	}{
		{"deleted", watch.Deleted, "client-uid", false, 1},
		{"deletion timestamp", watch.Modified, "client-uid", true, 1},
		{"replacement UID", watch.Added, "replacement", false, 1},
		{"stale deleted UID", watch.Deleted, "previous", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, pod, cancel, done, streams := watchFixture(t)
			defer finishWatch(t, cancel, done)
			w := nextStream(t, streams)
			eventPod := pod.DeepCopy()
			eventPod.UID = types.UID(tc.uid)
			if tc.deleting {
				now := metav1.Now()
				eventPod.DeletionTimestamp = &now
			}
			switch tc.event {
			case watch.Deleted:
				w.Delete(eventPod)
			case watch.Added:
				w.Add(eventPod)
			default:
				w.Modify(eventPod)
			}
			if tc.want > 0 {
				waitRemoved(t, s, p, tc.want)
			} else {
				time.Sleep(50 * time.Millisecond)
				s.mu.Lock()
				got := p.removed
				s.mu.Unlock()
				if got != 0 {
					t.Fatalf("stale deletion removed newer binding: %d", got)
				}
			}
		})
	}
}
func TestWatchReconnectReconcilesMissedDeletion(t *testing.T) {
	s, p, pod, cancel, done, streams := watchFixture(t)
	defer finishWatch(t, cancel, done)
	first := nextStream(t, streams)
	// The deletion is missed while the stream is down; relisting and validating
	// against the uncached reader must promptly remove the bound peer.
	if err := s.Reader.(client.Client).Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	first.Stop()
	_ = nextStream(t, streams)
	waitRemoved(t, s, p, 1)
}
func TestWatchCanceledContext(t *testing.T) {
	_, _, _, cancel, done, streams := watchFixture(t)
	w := nextStream(t, streams)
	finishWatch(t, cancel, done)
	select {
	case <-w.ResultChan():
	default:
		t.Fatal("watch stream not stopped")
	}
}
