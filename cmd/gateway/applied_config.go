package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sync/atomic"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

// POD_UID is required even without encrypted peer registration: an applied hash
// from a replaced pod must never acknowledge a different gateway process.
func validatePodUID(uid string) error {
	if len(uid) != 36 {
		return errors.New("POD_UID must be a UUID from the Downward API")
	}
	for i, ch := range uid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return errors.New("POD_UID must be a UUID from the Downward API")
			}
			continue
		}
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return errors.New("POD_UID must be a UUID from the Downward API")
		}
	}
	return nil
}

// info intentionally exposes only the existing health/MTU data and these two
// proof fields, never selected clients, raw config, credentials or private keys.
func gatewayInfoHandler(current *atomic.Value) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s := current.Load().(state)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			ExitIP                  string `json:"exitIP"`
			Ready                   bool   `json:"ready"`
			PodMTU                  int    `json:"podMTU"`
			GeneveMTU               int    `json:"geneveMTU"`
			WireguardMTU            int    `json:"wireguardMTU"`
			UpstreamMTU             int    `json:"upstreamMTU"`
			EffectiveMTU            int    `json:"effectiveMTU"`
			MSS                     int    `json:"mss"`
			PodUID                  string `json:"podUID"`
			AppliedClientConfigHash string `json:"appliedClientConfigHash"`
		}{s.exitIP, s.ready, s.podMTU, s.geneveMTU, s.wireguardMTU, s.upstreamMTU, s.effectiveMTU, s.mss, s.podUID, s.appliedClientConfigHash})
	}
}

// gatewayReconciler has one writer (the poll loop); HTTP readers see immutable
// snapshots through atomic.Value. cfg and appliedHash describe only a successful
// backend application, never an attempted/optimistic desired state.
type gatewayReconciler struct {
	current     *atomic.Value
	podUID      string
	cfg         datapath.GatewayConfig
	appliedHash string
	previous    state
	apply       func(context.Context, datapath.GatewayConfig) error
}

func (g *gatewayReconciler) invalidate() {
	g.appliedHash = ""
	g.current.Store(state{podUID: g.podUID})
}

func (g *gatewayReconciler) failClosed(ctx context.Context, clearClients bool) error {
	// Revoke proof and readiness BEFORE any backend mutation, including shutdown.
	g.invalidate()
	closed := g.cfg
	closed.UpstreamHealthy = false
	if clearClients {
		closed.Clients = nil
	}
	if err := g.apply(ctx, closed); err != nil {
		return errors.New("gateway fail-closed application failed")
	}
	g.cfg = closed
	g.previous = state{}
	return nil
}

func (g *gatewayReconciler) refresh(ctx context.Context,
	read func() (datapath.GatewayConfig, string, error),
	clamp func(*datapath.GatewayConfig) error,
	probe func(string) (state, error)) error {
	next, hash, err := read()
	if err == nil {
		err = clamp(&next)
	}
	if err != nil {
		if applyErr := g.failClosed(ctx, true); applyErr != nil {
			return applyErr
		}
		return errors.New("gateway config unavailable or invalid")
	}
	// An unchanged successful projection keeps its truthful last-applied proof
	// while reading/probing. Changed bytes cannot acknowledge the old client set.
	if hash != g.appliedHash {
		g.invalidate()
	}
	observed, err := probe(next.Encryption)
	if err != nil {
		observed = state{}
	}
	if !observed.ready {
		g.invalidate()
	}
	next.UpstreamHealthy = observed.ready
	// Empty appliedHash forces a retry after EVERY failed ApplyGateway, even if
	// desired bytes/health equal the last attempt. Never commit cfg on failure.
	if g.appliedHash == "" || hash != g.appliedHash || !reflect.DeepEqual(g.cfg, next) || observed != g.previous || !observed.ready {
		g.invalidate()
		if err := g.apply(ctx, next); err != nil {
			return errors.New("gateway datapath application failed")
		}
		g.cfg = next
		g.previous = observed
		if observed.ready {
			g.appliedHash = hash
		}
	}
	observed.podUID = g.podUID
	observed.appliedClientConfigHash = g.appliedHash
	g.current.Store(observed)
	return nil
}
