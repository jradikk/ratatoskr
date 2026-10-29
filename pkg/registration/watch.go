package registration

import (
	"context"
	"time"

	"errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

var errWatchUnavailable = errors.New("registration unavailable")

const (
	podWatchRetryMin = time.Second
	podWatchRetryMax = 30 * time.Second
)

// WatchPods tracks the selected gateway's Pods across namespaces and removes
// registered peers as soon as deletion or a replacement UID is observed. It
// lists before every watch to obtain a fresh resourceVersion, reconciles peers
// against uncached API reads on each reconnect, and retries with bounded
// backoff. Run alongside periodic ReconcilePeers for namespace/gateway changes
// and the TTL backstop. The caller must grant pods list/watch cluster-wide.
// A narrow gateway label selector limits watch traffic; label opt-outs are
// reported as Deleted watch events by the Kubernetes selector transition.
func (s *Server) WatchPods(ctx context.Context) error {
	if !s.ready() {
		return errWatchUnavailable
	}
	retry := podWatchRetryMin
	for ctx.Err() == nil {
		pods := s.Kubernetes.CoreV1().Pods("")
		options := metav1.ListOptions{LabelSelector: gatewayLabel + "=" + s.Identity.GatewayName}
		listed, err := pods.List(ctx, options)
		if err == nil {
			// Reconcile the current snapshot before watching so a deletion
			// during the initial list cannot leave a stale peer. The follow-up
			// watch resumes at its resourceVersion and replays newer events.
			_ = s.ReconcilePeers(ctx)
			options.ResourceVersion = listed.ResourceVersion
			options.AllowWatchBookmarks = true
			options.TimeoutSeconds = int64Ptr(300)
			stream, watchErr := pods.Watch(ctx, options)
			if watchErr == nil {
				retry = podWatchRetryMin
				s.consumePodWatch(ctx, stream)
			}
		}
		if ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if retry < podWatchRetryMax {
			retry *= 2
			if retry > podWatchRetryMax {
				retry = podWatchRetryMax
			}
		}
	}
	return nil
}

func int64Ptr(n int64) *int64 { return &n }

func (s *Server) consumePodWatch(ctx context.Context, stream watch.Interface) {
	defer stream.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-stream.ResultChan():
			if !ok || event.Type == watch.Error {
				return
			}
			pod, ok := event.Object.(*corev1.Pod)
			if !ok || pod == nil {
				continue
			}
			id := pod.Namespace + "/" + pod.Name
			s.mu.Lock()
			bound, exists := s.bindings[id]
			s.mu.Unlock()
			if !exists {
				continue
			}
			// A delayed Deleted event for a prior UID must never remove a
			// newer Pod's binding. A replacement Added/Modified UID does
			// revoke the old binding immediately.
			if event.Type == watch.Deleted && string(pod.UID) != bound.uid {
				continue
			}
			if event.Type == watch.Deleted || pod.DeletionTimestamp != nil || string(pod.UID) != bound.uid {
				_ = s.RemoveDeletedPod(ctx, pod.Namespace, pod.Name, bound.uid)
			}
		}
	}
}
