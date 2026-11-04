//go:build linux

package agent

import (
	"errors"
	"fmt"
	"testing"
)

func TestAgentReadinessSeparatesWorkloadFailures(t *testing.T) {
	failure := &workloadReconciliationFailures{count: 1}
	for _, tc := range []struct {
		name              string
		syncErr, watchErr error
		ready             bool
	}{
		{"healthy", nil, nil, true},
		{"isolated workload", failure, nil, true},
		{"multiple workloads", &workloadReconciliationFailures{count: 3}, nil, true},
		{"node list failure", errors.New("cannot list node Pods"), nil, false},
		{"own identity failure", errors.New("invalid agent identity"), nil, false},
		{"watch failure", nil, errors.New("watch denied"), false},
		{"workload and watch failure", failure, errors.New("watch lost"), false},
		{"wrapped infrastructure error", fmt.Errorf("node operation failed: %w", failure), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentReadyAfterSync(tc.syncErr, tc.watchErr); got != tc.ready {
				t.Fatalf("ready=%t want=%t", got, tc.ready)
			}
		})
	}
	if failure.Error() != "1 pod reconciliations failed" {
		t.Fatal("workload failure diagnostics lost")
	}
}
