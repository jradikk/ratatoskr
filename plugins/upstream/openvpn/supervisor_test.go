package openvpn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSettings() Settings {
	return Settings{5 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 30 * time.Millisecond, 10 * time.Millisecond, 40 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
}
func TestHealthAndInfo(t *testing.T) {
	s, err := NewSupervisor(DefaultSettings(), func(context.Context) (Process, error) { return nil, errors.New("unused") }, func(context.Context) (ProbeResult, error) { return ProbeResult{}, errors.New("unused") })
	if err != nil {
		t.Fatal(err)
	}
	check := func(status int, exit string) {
		t.Helper()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
		if w.Code != status {
			t.Fatalf("status %d, want %d", w.Code, status)
		}
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/info", nil))
		var info Info
		if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		if info.ExitIP != exit || info.HandshakeAge != nil || info.Details["interface"] != "upstream0" {
			t.Fatal("incorrect info state")
		}
	}
	check(503, "")
	s.clear(true)
	s.record(ProbeResult{"203.0.113.1", 1400}, nil)
	check(200, "203.0.113.1")
	s.mu.Lock()
	s.lastSuccess = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	check(503, "")
	s.record(ProbeResult{"203.0.113.1", 1400}, nil)
	s.record(ProbeResult{}, errors.New("synthetic failure"))
	check(503, "")
	s.record(ProbeResult{"203.0.113.1", 1400}, nil)
	exited := make(chan struct{})
	close(exited)
	s.mu.Lock()
	s.processDone = exited
	s.mu.Unlock()
	check(503, "")
	s.clear(false)
	check(503, "")
	for _, path := range []string{"/healthz", "/info"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 405 {
			t.Fatal("non-GET accepted")
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/unknown", nil))
	if w.Code != 404 {
		t.Fatal("unknown path accepted")
	}
}

type fakeProcess struct {
	done    chan struct{}
	once    sync.Once
	stopped atomic.Bool
	stopErr error
}

func newFakeProcess() *fakeProcess           { return &fakeProcess{done: make(chan struct{})} }
func (p *fakeProcess) Done() <-chan struct{} { return p.done }
func (p *fakeProcess) Stop(context.Context) error {
	p.stopped.Store(true)
	if p.stopErr != nil {
		return p.stopErr
	}
	p.once.Do(func() { close(p.done) })
	return nil
}
func awaitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not finish within bound")
		return nil
	}
}
func TestSupervisorProlongedFailuresAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan *fakeProcess, 8)
	var last *fakeProcess
	s, err := NewSupervisor(testSettings(), func(context.Context) (Process, error) {
		if last != nil && !last.stopped.Load() {
			return nil, errors.New("overlapping process")
		}
		last = newFakeProcess()
		started <- last
		return last, nil
	}, func(context.Context) (ProbeResult, error) { return ProbeResult{}, errors.New("synthetic failed probe") })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("expected bounded restart")
		}
	}
	cancel()
	if err := awaitRun(t, done); err != nil {
		t.Fatal(err)
	}
	if !last.stopped.Load() {
		t.Fatal("cancellation did not stop child")
	}
	if _, ok := s.Snapshot(); ok {
		t.Fatal("health survived shutdown")
	}
}
func TestSupervisorStartFailuresBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := testSettings()
	s, _ := NewSupervisor(settings, func(context.Context) (Process, error) { return nil, errors.New("synthetic start failure") }, func(context.Context) (ProbeResult, error) {
		t.Error("probe called without child")
		return ProbeResult{}, nil
	})
	var waits []time.Duration
	s.pause = func(_ context.Context, d time.Duration) bool { waits = append(waits, d); return len(waits) < 5 }
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 40 * time.Millisecond, 40 * time.Millisecond}
	for i, d := range waits {
		if d != want[i] {
			t.Fatal("backoff not exponentially capped")
		}
	}
}
func TestSupervisorBackoffResetsAfterStableHealth(t *testing.T) {
	settings := testSettings()
	settings.StableAfter = time.Nanosecond
	calls := 0
	p := newFakeProcess()
	probes := 0
	s, _ := NewSupervisor(settings, func(context.Context) (Process, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("synthetic failure")
		}
		return p, nil
	}, func(context.Context) (ProbeResult, error) {
		probes++
		if probes == 3 {
			p.once.Do(func() { close(p.done) })
		}
		return ProbeResult{"203.0.113.1", 1400}, nil
	})
	var waits []time.Duration
	s.pause = func(_ context.Context, d time.Duration) bool { waits = append(waits, d); return len(waits) < 3 }
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()
	if err := awaitRun(t, done); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 3 || waits[0] != settings.MinBackoff || waits[1] != 2*settings.MinBackoff || waits[2] != settings.MinBackoff {
		t.Fatal("sustained health did not reset backoff")
	}
}
func TestSupervisorUnexpectedExitAndHealthyProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan *fakeProcess, 3)
	s, _ := NewSupervisor(testSettings(), func(context.Context) (Process, error) { p := newFakeProcess(); started <- p; return p, nil }, func(context.Context) (ProbeResult, error) { return ProbeResult{"203.0.113.10", 1420}, nil })
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	var p *fakeProcess
	select {
	case p = <-started:
	case <-time.After(time.Second):
		t.Fatal("no process")
	}
	// The notification arrives just before record; inspect health with a bounded
	// timer rather than depending on scheduler ordering.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if _, ok := s.Snapshot(); ok {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("no healthy state")
		}
	}
	p.once.Do(func() { close(p.done) })
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("exited child not restarted")
	}
	cancel()
	if err := awaitRun(t, done); err != nil {
		t.Fatal(err)
	}
}
func TestSupervisorProbeTimeoutAndUnreapedChild(t *testing.T) {
	p := newFakeProcess()
	p.stopErr = errors.New("synthetic stuck child")
	var starts atomic.Int32
	s, _ := NewSupervisor(testSettings(), func(context.Context) (Process, error) { starts.Add(1); return p, nil }, func(ctx context.Context) (ProbeResult, error) { <-ctx.Done(); return ProbeResult{}, ctx.Err() })
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()
	if err := awaitRun(t, done); err == nil {
		t.Fatal("unreaped child not fatal")
	}
	if starts.Load() != 1 {
		t.Fatal("replacement started before reap")
	}
}
func TestInvalidSettings(t *testing.T) {
	if _, err := NewSupervisor(Settings{}, nil, nil); err == nil {
		t.Fatal("invalid settings accepted")
	}
}
