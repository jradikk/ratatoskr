package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

const testPodUID = "1ab87f00-5d0a-4b9e-9661-aa4455667788"
const configA = `{"podIP":"10.42.2.4","gatewayID":7,"mtu":1400,"clients":["10.42.1.8"]}`
const configB = `{"podIP":"10.42.2.4","gatewayID":7,"mtu":1400,"clients":["10.42.1.8","10.42.1.9"]}`

func configHash(raw string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) }
func snapshot(t *testing.T, raw string) (datapath.GatewayConfig, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, hash, err := readGatewayConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, hash
}
func goodProbe(string) (state, error) {
	return state{ready: true, exitIP: "203.0.113.8", effectiveMTU: 1400}, nil
}
func noClamp(*datapath.GatewayConfig) error { return nil }
func readSnapshot(cfg datapath.GatewayConfig, hash string) func() (datapath.GatewayConfig, string, error) {
	return func() (datapath.GatewayConfig, string, error) { return cfg, hash, nil }
}
func newReconciler() *gatewayReconciler {
	var current atomic.Value
	current.Store(state{podUID: testPodUID})
	return &gatewayReconciler{current: &current, podUID: testPodUID, apply: func(context.Context, datapath.GatewayConfig) error { return nil }}
}
func publicState(t *testing.T, g *gatewayReconciler, hash string, ready bool) {
	t.Helper()
	s := g.current.Load().(state)
	if s.podUID != testPodUID || s.appliedClientConfigHash != hash || s.ready != ready {
		t.Fatalf("unexpected acknowledgment state: UID=%s hash=%s ready=%t", s.podUID, s.appliedClientConfigHash, s.ready)
	}
}

func TestGatewaySnapshotHashExactProjectedBytes(t *testing.T) {
	root := t.TempDir()
	for name, raw := range map[string]string{"old": configA, "new": configB + "\n"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "gateway.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pointer := filepath.Join(root, "..data")
	if err := os.Symlink("old", pointer); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "gateway.json")
	if err := os.Symlink("..data/gateway.json", path); err != nil {
		t.Fatal(err)
	}
	old, oldHash, err := readGatewayConfigSnapshot(path)
	if err != nil || oldHash != configHash(configA) || len(old.Clients) != 1 {
		t.Fatal("old projection snapshot mismatch")
	}
	next := filepath.Join(root, "..next")
	if err := os.Symlink("new", next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, pointer); err != nil {
		t.Fatal(err)
	}
	updated, newHash, err := readGatewayConfigSnapshot(path)
	if err != nil || newHash != configHash(configB+"\n") || len(updated.Clients) != 2 {
		t.Fatal("new projection snapshot mismatch")
	}
	if len(old.Clients) != 1 || oldHash != configHash(configA) {
		t.Fatal("captured snapshot changed after symlink replacement")
	}
	_, compactHash := snapshot(t, configB)
	if compactHash == newHash {
		t.Fatal("hash was computed from normalized JSON rather than exact bytes")
	}
}

func TestGatewayStaleProjectionAndUnchangedPollKeepProof(t *testing.T) {
	cfg, hash := snapshot(t, configA)
	g := newReconciler()
	applies := 0
	g.apply = func(context.Context, datapath.GatewayConfig) error {
		applies++
		publicState(t, g, "", false)
		return nil
	}
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	publicState(t, g, hash, true)
	// Controller may have changed desired ConfigMap already; only the actually
	// projected bytes are acknowledged, not an optimistic desired client set.
	if err := g.refresh(context.Background(), func() (datapath.GatewayConfig, string, error) { publicState(t, g, hash, true); return cfg, hash, nil }, noClamp, func(string) (state, error) { publicState(t, g, hash, true); return goodProbe("") }); err != nil {
		t.Fatal(err)
	}
	if applies != 1 {
		t.Fatal("unchanged successful polling reapplied or churned acknowledgment")
	}
	publicState(t, g, hash, true)
	newer, newHash := snapshot(t, configB)
	if err := g.refresh(context.Background(), readSnapshot(newer, newHash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	if applies != 2 {
		t.Fatal("new projection was not applied")
	}
	publicState(t, g, newHash, true)
}

func TestGatewayExactByteChangeForcesApplication(t *testing.T) {
	cfg, hash := snapshot(t, configA)
	same, otherHash := snapshot(t, configA+"\n")
	g := newReconciler()
	applies := 0
	g.apply = func(context.Context, datapath.GatewayConfig) error {
		applies++
		publicState(t, g, "", false)
		return nil
	}
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	if err := g.refresh(context.Background(), readSnapshot(same, otherHash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	if applies != 2 {
		t.Fatal("semantically equal changed bytes were not actually applied before acknowledgment")
	}
	publicState(t, g, otherHash, true)
}

func TestGatewayFailuresClearProofBeforeApplication(t *testing.T) {
	for _, failure := range []string{"invalid file", "invalid MTU", "probe", "apply"} {
		t.Run(failure, func(t *testing.T) {
			cfg, hash := snapshot(t, configA)
			g := newReconciler()
			if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
				t.Fatal(err)
			}
			reader := readSnapshot(cfg, hash)
			clamp := noClamp
			prober := goodProbe
			sentinel := errors.New("synthetic failure")
			switch failure {
			case "invalid file":
				reader = func() (datapath.GatewayConfig, string, error) { return datapath.GatewayConfig{}, "", sentinel }
			case "invalid MTU":
				clamp = func(*datapath.GatewayConfig) error { return sentinel }
			case "probe":
				prober = func(string) (state, error) { return state{ready: true}, sentinel }
			case "apply":
				cfg.MTU--
				reader = readSnapshot(cfg, hash)
			}
			g.apply = func(_ context.Context, applied datapath.GatewayConfig) error {
				publicState(t, g, "", false)
				if failure == "apply" {
					return sentinel
				}
				if applied.UpstreamHealthy {
					t.Fatal("failure retained healthy accept rules")
				}
				if (failure == "invalid file" || failure == "invalid MTU") && len(applied.Clients) != 0 {
					t.Fatal("invalid config retained stale selected client permissions")
				}
				return nil
			}
			err := g.refresh(context.Background(), reader, clamp, prober)
			if failure != "probe" && err == nil {
				t.Fatal("failure not reported")
			}
			publicState(t, g, "", false)
		})
	}
}

func TestGatewayFailedChangedApplicationRetriesUnchangedHealthyTick(t *testing.T) {
	cfg, hash := snapshot(t, configA)
	next, nextHash := snapshot(t, configB)
	g := newReconciler()
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	g.apply = func(context.Context, datapath.GatewayConfig) error {
		attempts++
		publicState(t, g, "", false)
		if attempts == 1 {
			return errors.New("synthetic application failure")
		}
		return nil
	}
	if err := g.refresh(context.Background(), readSnapshot(next, nextHash), noClamp, goodProbe); err == nil {
		t.Fatal("application failure not returned")
	}
	publicState(t, g, "", false)
	if len(g.cfg.Clients) != 1 {
		t.Fatal("failed desired config was committed as already applied")
	}
	if err := g.refresh(context.Background(), readSnapshot(next, nextHash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatal("empty acknowledgment did not force retry of unchanged healthy tick")
	}
	publicState(t, g, nextHash, true)
}

func TestGatewayHealthChangeRevokesProofBeforeMutation(t *testing.T) {
	cfg, hash := snapshot(t, configA)
	g := newReconciler()
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	g.apply = func(context.Context, datapath.GatewayConfig) error { publicState(t, g, "", false); return nil }
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, func(string) (state, error) { s, _ := goodProbe(""); s.upstreamIndex = 2; return s, nil }); err != nil {
		t.Fatal(err)
	}
	publicState(t, g, hash, true)
	if err := g.failClosed(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	publicState(t, g, "", false)
}

func TestGatewayInvalidConfigNeverReturnsHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	for _, raw := range []string{"", "{", configA + " {}", `{"podIP":"10.42.2.4","gatewayID":0,"mtu":1400,"clients":[]}`, configA[:len(configA)-1] + `,"secret":"synthetic-private-value"}`, strings.Repeat("x", 1<<20+1)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, hash, err := readGatewayConfigSnapshot(path)
		if err == nil || hash != "" {
			t.Fatal("invalid config returned applied candidate hash")
		}
		if strings.Contains(err.Error(), "synthetic-private-value") {
			t.Fatal("config contents leaked in error")
		}
	}
}

func TestGatewayInfoProofFieldsDoNotExposeClients(t *testing.T) {
	cfg, hash := snapshot(t, configB)
	g := newReconciler()
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	gatewayInfoHandler(g.current)(response, httptest.NewRequest("GET", "/info", nil))
	var info map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	var uid, applied string
	if err := json.Unmarshal(info["podUID"], &uid); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(info["appliedClientConfigHash"], &applied); err != nil {
		t.Fatal(err)
	}
	if uid != testPodUID || applied != hash || len(applied) != 64 {
		t.Fatal("missing proof fields")
	}
	if _, ok := info["clients"]; ok {
		t.Fatal("client identities exposed")
	}
	if strings.Contains(response.Body.String(), "10.42.1.8") || strings.Contains(response.Body.String(), "10.42.1.9") {
		t.Fatal("raw client config exposed")
	}
}

func TestGatewayPodUIDRequiredAndValidAtStartup(t *testing.T) {
	if err := validatePodUID(testPodUID); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"", "pod-name", "1ab87f00-5d0a-4b9e-9661-aa445566778z", "1ab87f00_5d0a-4b9e-9661-aa4455667788"} {
		if err := validatePodUID(uid); err == nil {
			t.Fatal("invalid POD_UID accepted")
		}
	}
	t.Setenv("POD_UID", "")
	if err := run(context.Background(), "unused"); err == nil || !strings.Contains(err.Error(), "POD_UID") {
		t.Fatal("missing POD_UID was not rejected before kernel/backend startup")
	}
}

func TestGatewayInfoAtomicDuringBlockedApplication(t *testing.T) {
	cfg, hash := snapshot(t, configA)
	next, nextHash := snapshot(t, configB)
	g := newReconciler()
	if err := g.refresh(context.Background(), readSnapshot(cfg, hash), noClamp, goodProbe); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	g.apply = func(context.Context, datapath.GatewayConfig) error { close(entered); <-release; return nil }
	go func() { done <- g.refresh(context.Background(), readSnapshot(next, nextHash), noClamp, goodProbe) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("application did not begin")
	}
	for i := 0; i < 100; i++ {
		response := httptest.NewRecorder()
		gatewayInfoHandler(g.current)(response, httptest.NewRequest("GET", "/info", nil))
		var info struct {
			PodUID string `json:"podUID"`
			Hash   string `json:"appliedClientConfigHash"`
			Ready  bool   `json:"ready"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		if info.PodUID != testPodUID || info.Hash != "" || info.Ready {
			t.Fatal("HTTP observed optimistic or mixed acknowledgment during application")
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("application did not complete")
	}
	publicState(t, g, nextHash, true)
}
