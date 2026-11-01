//go:build linux

package agent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/observability"
)

func TestReconcilerObserveProgramNilAndCompleted(t *testing.T) {
	r := &Reconciler{}
	calls := 0
	failure := errors.New("private selected workload UID")
	if err := r.observeProgram(observability.AgentUsable, func() error { calls++; return failure }); !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("nil observer changed original call: %v calls=%d", err, calls)
	}
	r.Programming = observability.NewAgentProgramming()
	if err := r.observeProgram(observability.AgentClosed, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.observeProgram(observability.AgentCleanup, func() error { calls++; return failure }); !errors.Is(err, failure) {
		t.Fatal("cleanup error changed")
	}
	if calls != 3 {
		t.Fatalf("programming calls=%d", calls)
	}
	w := httptest.NewRecorder()
	observability.AgentHandler(r.Programming).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status=%d", w.Code)
	}
	got := w.Body.String()
	for _, want := range []string{
		`ratatoskr_agent_programming_attempts_total{operation="closed"} 1`,
		`ratatoskr_agent_programming_attempts_total{operation="cleanup"} 1`,
		`ratatoskr_agent_programming_errors_total{operation="cleanup"} 1`,
		`ratatoskr_agent_programming_attempts_total{operation="usable"} 0`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing metric %q", want)
		}
	}
	if strings.Contains(got, "private selected workload UID") {
		t.Fatal("private error text leaked into agent metrics")
	}
}
