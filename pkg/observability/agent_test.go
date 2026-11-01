package observability

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAgentProgrammingCompletedOnlyAndPrivateLabels(t *testing.T) {
	p := NewAgentProgramming()
	handler := AgentHandler(p)
	initial := metricText(t, handler)
	for _, operation := range agentOperations {
		metricLine(t, initial, fmt.Sprintf("ratatoskr_agent_programming_attempts_total{operation=%q} 0", operation))
		metricLine(t, initial, fmt.Sprintf("ratatoskr_agent_programming_errors_total{operation=%q} 0", operation))
		metricLine(t, initial, fmt.Sprintf("ratatoskr_agent_programming_duration_seconds_count{operation=%q} 0", operation))
	}
	private := errors.New("private Pod UID token and IP 10.42.1.8")
	if err := p.Observe(AgentUsable, func() error { time.Sleep(time.Millisecond); return private }); !errors.Is(err, private) {
		t.Fatal("programming error changed")
	}
	if err := p.Observe(AgentClosed, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.Observe(AgentCleanup, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	got := metricText(t, handler)
	for _, operation := range agentOperations {
		metricLine(t, got, fmt.Sprintf("ratatoskr_agent_programming_attempts_total{operation=%q} 1", operation))
		metricLine(t, got, fmt.Sprintf("ratatoskr_agent_programming_duration_seconds_count{operation=%q} 1", operation))
		wantErrors := 0
		if operation == AgentUsable {
			wantErrors = 1
		}
		metricLine(t, got, fmt.Sprintf("ratatoskr_agent_programming_errors_total{operation=%q} %d", operation, wantErrors))
	}
	for _, forbidden := range []string{"private", "10.42.1.8", "uid=", "go_gc_duration", "process_cpu", "ratatoskr_gateway_", "ratatoskr_wireguard_"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("agent metrics leaked %q", forbidden)
		}
	}
	if strings.Count(got, "ratatoskr_agent_programming_attempts_total{") != len(agentOperations) {
		t.Fatal("unexpected operation label cardinality")
	}
}

func TestAgentProgrammingConcurrentPanicAndUnknownOperation(t *testing.T) {
	p := NewAgentProgramming()
	var group sync.WaitGroup
	for i := 0; i < 48; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			_ = p.Observe(agentOperations[i%len(agentOperations)], func() error {
				if i%2 != 0 {
					return errors.New("not exported")
				}
				return nil
			})
		}(i)
	}
	group.Wait()
	func() {
		defer func() {
			if recover() != "expected-panic" {
				t.Fatal("programming panic swallowed")
			}
		}()
		_ = p.Observe(AgentUsable, func() error { panic("expected-panic") })
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("unbounded operation was accepted")
			}
		}()
		_ = p.Observe("pod-private-uid", func() error { t.Fatal("unknown operation invoked"); return nil })
	}()
	got := metricText(t, AgentHandler(p))
	for _, operation := range agentOperations {
		metricLine(t, got, fmt.Sprintf("ratatoskr_agent_programming_attempts_total{operation=%q} 16", operation))
		metricLine(t, got, fmt.Sprintf("ratatoskr_agent_programming_errors_total{operation=%q} 8", operation))
		metricLine(t, got, fmt.Sprintf("ratatoskr_agent_programming_duration_seconds_count{operation=%q} 16", operation))
	}
	if strings.Contains(got, "pod-private-uid") {
		t.Fatal("unknown operation leaked to registry")
	}
}

func TestAgentHandlerContainsOnlyMetrics(t *testing.T) {
	got := metricText(t, AgentHandler(NewAgentProgramming()))
	if !strings.Contains(got, "ratatoskr_agent_programming_attempts_total") {
		t.Fatal("missing completed attempt counters")
	}
	for _, forbidden := range []string{"go_gc_duration", "process_cpu", "ratatoskr_gateway_", "ratatoskr_wireguard_"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("unrelated metrics leaked %q", forbidden)
		}
	}
}
