package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

const gatewayOwnerUID = "a76addbc-e3ad-4d04-a61b-c13d9876c2ab"

func configCM(raw, rv string) *corev1.ConfigMap {
	controlled := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "gateways", UID: types.UID("f0534dbc-48ca-44c1-8d91-3bccfe1c0d44"), ResourceVersion: rv, OwnerReferences: []metav1.OwnerReference{{APIVersion: api.SchemeGroupVersion.String(), Kind: "EgressGateway", Name: "vpn", UID: types.UID(gatewayOwnerUID), Controller: &controlled}}}, Data: map[string]string{"gateway.json": raw}}
}
func testAPISource(reader configMapAPI) *gatewayConfigSource {
	return &gatewayConfigSource{namespace: "gateways", name: "vpn", ownerUID: gatewayOwnerUID, podIP: "10.42.2.4", api: reader, notify: make(chan struct{}, 1), err: errors.New("unsynced")}
}

type cmReader struct {
	mu                   sync.Mutex
	cm                   *corev1.ConfigMap
	stream               *watch.FakeWatcher
	getErr, watchErr     error
	getCount, watchCount int
	options              metav1.ListOptions
}

func (r *cmReader) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getCount++
	if name != "vpn" {
		return nil, errors.New("unscoped GET")
	}
	if r.getErr != nil {
		return nil, r.getErr
	}
	return r.cm.DeepCopy(), nil
}
func (r *cmReader) Watch(_ context.Context, option metav1.ListOptions) (watch.Interface, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.watchCount++
	r.options = option
	if r.watchErr != nil {
		return nil, r.watchErr
	}
	return r.stream, nil
}
func TestGatewayAPIConfigValidatesIdentityAndHash(t *testing.T) {
	reader := &cmReader{cm: configCM(configA, "5"), stream: watch.NewFake()}
	source := testAPISource(reader)
	source.accept(reader.cm)
	cfg, hash, err := source.Snapshot()
	if err != nil || hash != configHash(configA) || len(cfg.Clients) != 1 {
		t.Fatalf("accepted cfg=%+v hash=%q err=%v", cfg, hash, err)
	}
	malformed := configCM(`{"podIP":"10.42.2.4","gatewayID":7,"mtu":1400,"clients":["10.42.1.8"],"unknown":true}`, "6")
	source.accept(malformed)
	if _, hash, err = source.Snapshot(); err == nil || hash != "" {
		t.Fatal("malformed update retained ack")
	}
	foreign := configCM(configB, "7")
	foreign.OwnerReferences[0].UID = "foreign"
	source.accept(foreign)
	if _, hash, err = source.Snapshot(); err == nil || hash != "" {
		t.Fatal("wrong owner gained ack")
	}
	replacement := configCM(configB, "8")
	replacement.UID = "recreated"
	source.accept(replacement)
	if _, hash, err = source.Snapshot(); err == nil || hash != "" {
		t.Fatal("recreated ConfigMap gained ack")
	}
	source.accept(configCM(configB, "9"))
	if cfg, hash, err = source.Snapshot(); err != nil || hash != configHash(configB) || len(cfg.Clients) != 2 {
		t.Fatal("legitimate update did not recover")
	}
}
func TestGatewayAPIConfigWatchImmediateWakeAndOutageRevokesAck(t *testing.T) {
	reader := &cmReader{cm: configCM(configA, "10"), stream: watch.NewFake()}
	source := testAPISource(reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- source.watchOnce(ctx) }()
	wait := func(want string) {
		t.Helper()
		select {
		case <-source.notify:
		case <-time.After(time.Second):
			t.Fatal("config watch failed to wake gateway")
		}
		_, hash, err := source.Snapshot()
		if err != nil || hash != want {
			t.Fatalf("hash=%q err=%v want=%q", hash, err, want)
		}
	}
	wait(configHash(configA))
	reader.mu.Lock()
	options := reader.options
	reader.mu.Unlock()
	if options.FieldSelector != "metadata.name=vpn" || options.ResourceVersion != "10" {
		t.Fatalf("unscoped watch: %+v", options)
	}
	reader.stream.Modify(configCM(configB, "11"))
	wait(configHash(configB))
	reader.stream.Error(&metav1.Status{Reason: metav1.StatusReasonExpired})
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("watch expiration ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("watch error blocked")
	}
	// Source's run loop revokes before reconnect; watchOnce callers explicitly
	// use invalidate before proceeding to another GET.
	source.invalidate(errors.New("watch error"))
	if _, hash, err := source.Snapshot(); err == nil || hash != "" {
		t.Fatal("lost watch kept acknowledged hash")
	}
}
func TestGatewayAPIConfigEventRefreshWithoutProbeTicker(t *testing.T) {
	reader := &cmReader{cm: configCM(configA, "1"), stream: watch.NewFake()}
	source := testAPISource(reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- source.watchOnce(ctx) }()
	select {
	case <-source.notify:
	case <-time.After(time.Second):
		t.Fatal("initial config delayed")
	}
	var writes atomic.Int32
	g := newReconciler()
	g.apply = func(_ context.Context, cfg datapath.GatewayConfig) error { writes.Add(1); return nil }
	refresh := func() {
		t.Helper()
		if err := g.refresh(ctx, source.Snapshot, noClamp, goodProbe); err != nil {
			t.Fatal(err)
		}
	}
	refresh()
	publicState(t, g, configHash(configA), true)
	reader.stream.Modify(configCM(configB, "2"))
	select {
	case <-source.notify:
	case <-time.After(time.Second):
		t.Fatal("config update delayed by 2s poll")
	}
	refresh()
	publicState(t, g, configHash(configB), true)
	if writes.Load() != 2 || len(g.cfg.Clients) != 2 {
		t.Fatalf("updated client set not applied: %+v writes=%d", g.cfg, writes.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("watch cancellation blocked")
	}
}

// Normal server watch expiry must NOT revoke an unchanged applied hash every
// TimeoutSeconds=30. Resync GET/watch is immediate; failure instead revokes it.
func TestGatewayAPIConfigNormalWatchRenewalKeepsAckUntilBoundedGET(t *testing.T) {
	reader := &cmReader{cm: configCM(configA, "10"), stream: watch.NewFake()}
	source := testAPISource(reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { source.run(ctx); close(done) }()
	select {
	case <-source.notify:
	case <-time.After(time.Second):
		t.Fatal("initial watch not ready")
	}
	_, hash, err := source.Snapshot()
	if err != nil || hash != configHash(configA) {
		t.Fatalf("initial hash=%s err=%v", hash, err)
	}
	reader.mu.Lock()
	stream := reader.stream
	reader.stream = watch.NewFake()
	reader.mu.Unlock()
	stream.Stop() // Kubernetes server's ordinary timeout/EOF
	deadline := time.Now().Add(time.Second)
	for {
		reader.mu.Lock()
		count := reader.watchCount
		reader.mu.Unlock()
		if count >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("normal watch not immediately renewed")
		}
		time.Sleep(time.Millisecond)
	}
	_, hash, err = source.Snapshot()
	if err != nil || hash != configHash(configA) {
		t.Fatalf("watch renewal withdrew stable ack hash=%s err=%v", hash, err)
	}
	select {
	case <-source.notify:
		t.Fatal("normal renewal falsely signaled config invalidation")
	default:
	}
	reader.mu.Lock()
	next := reader.stream
	reader.mu.Unlock()
	next.Stop()
	reader.mu.Lock()
	reader.getErr = errors.New("GET forbidden")
	reader.mu.Unlock()
	select {
	case <-source.notify:
	case <-time.After(time.Second):
		t.Fatal("failed renewal GET did not revoke ack")
	}
	_, hash, err = source.Snapshot()
	if err == nil || hash != "" {
		t.Fatalf("GET failure kept stale ack hash=%q err=%v", hash, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watch runner did not stop")
	}
}

func TestGatewayAPIConfigExplicitWatchErrorRevokesImmediately(t *testing.T) {
	reader := &cmReader{cm: configCM(configA, "10"), stream: watch.NewFake()}
	source := testAPISource(reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { source.run(ctx); close(done) }()
	select {
	case <-source.notify:
	case <-time.After(time.Second):
		t.Fatal("initial watch not ready")
	}
	reader.stream.Error(&metav1.Status{Reason: metav1.StatusReasonForbidden})
	select {
	case <-source.notify:
	case <-time.After(time.Second):
		t.Fatal("watch error retained ack")
	}
	_, hash, err := source.Snapshot()
	if err == nil || hash != "" {
		t.Fatalf("watch error retained stale hash %s err=%v", hash, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watch runner did not stop")
	}
}
