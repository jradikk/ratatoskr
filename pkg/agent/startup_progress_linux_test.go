//go:build linux

package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStartupProgressStageChangesAndRateLimitWithoutPrivateData(t *testing.T) {
	var output bytes.Buffer
	r := &Reconciler{Log: slog.New(slog.NewJSONHandler(&output, nil))}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "public-workload", Namespace: "apps", UID: "public-uid"}}
	r.startupStage(pod, "waiting-sandbox")
	r.startupStage(pod, "waiting-sandbox")
	if n := strings.Count(output.String(), "selected workload startup"); n != 1 {
		t.Fatalf("pending progress log flood: %d", n)
	}
	r.startupMu.Lock()
	state := r.startup[string(pod.UID)]
	state.last = time.Now().Add(-2 * time.Second)
	r.startup[string(pod.UID)] = state
	r.startupMu.Unlock()
	r.startupStage(pod, "waiting-sandbox")
	r.startupStage(pod, "waiting-config-ack")
	r.startupStage(pod, "programming")
	r.startupStage(pod, "ready")
	if n := strings.Count(output.String(), "selected workload startup"); n != 5 {
		t.Fatalf("missing transition/progress logs: %d", n)
	}
	if len(r.startup) != 0 {
		t.Fatal("ready workload retained unbounded progress state")
	}
	before := output.Len()
	r.startupStage(pod, "ready")
	r.startupStage(pod, "PRIVATE_CONFIG")
	if output.Len() != before || strings.Contains(output.String(), "PRIVATE_CONFIG") || strings.Contains(output.String(), "10.42.") {
		t.Fatal("ready workload flooded or dynamic private state logged")
	}
	r.startupStage(pod, "waiting-gateway")
	r.startupStage(pod, "failed")
	if len(r.startup) != 0 {
		t.Fatal("failed workload retained startup record")
	}
}
