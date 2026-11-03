//go:build linux

package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
)

type policyWatchClient struct {
	client.WithWatch
	started chan *watch.RaceFreeFakeWatcher
}

func (c policyWatchClient) Watch(ctx context.Context, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
	w := watch.NewRaceFreeFake()
	if _, ok := list.(*api.EgressPolicyList); ok {
		c.started <- w
	}
	return w, nil
}
func TestPolicyWatchTriggersPromptFullReconciliationAndStops(t *testing.T) {
	r, _, _, _, _, _, _, _ := domainFixture(t, "include")
	r.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	started := make(chan *watch.RaceFreeFakeWatcher, 4)
	r.WatchClient = policyWatchClient{started: started}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var first *watch.RaceFreeFakeWatcher
	select {
	case first = <-started:
	case <-time.After(time.Second):
		t.Fatal("policy watch not installed")
	}
	first.Modify(&api.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "domains", Namespace: "apps", UID: "policy-uid", Generation: 2}})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("policy update waited for30s periodic resync")
	}
	if !first.IsStopped() {
		t.Fatal("old policy watcher not stopped on reconnect")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("agent policy watcher did not shutdown")
	}
}
