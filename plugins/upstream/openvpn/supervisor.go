package openvpn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

type ProbeResult struct {
	ExitIP string
	MTU    int
}
type Probe func(context.Context) (ProbeResult, error)

// Process.Done closes only after the child has been reaped. Stop must wait for
// reaping or return an error; the supervisor never starts overlapping children.
type Process interface {
	Done() <-chan struct{}
	Stop(context.Context) error
}
type Starter func(context.Context) (Process, error)

type Settings struct {
	ProbeInterval, ProbeTimeout, Freshness, FailureTimeout time.Duration
	MinBackoff, MaxBackoff, StableAfter, StopTimeout       time.Duration
}

func DefaultSettings() Settings {
	return Settings{10 * time.Second, 5 * time.Second, 20 * time.Second, 60 * time.Second, time.Second, 30 * time.Second, 60 * time.Second, 5 * time.Second}
}
func (s Settings) valid() bool {
	return s.ProbeInterval > 0 && s.ProbeTimeout > 0 && s.Freshness >= s.ProbeInterval && s.FailureTimeout > 0 && s.MinBackoff > 0 && s.MaxBackoff >= s.MinBackoff && s.StableAfter > 0 && s.StopTimeout > 0
}

type Info struct {
	ExitIP       string            `json:"exitIP"`
	MTU          int               `json:"mtu"`
	HandshakeAge *float64          `json:"handshakeAge"`
	Details      map[string]string `json:"details"`
}

// Supervisor combines process lifetime and successful tunnel probes. State is
// cleared on every failed probe/exit/restart; HTTP never probes the network.
type Supervisor struct {
	pause            func(context.Context, time.Duration) bool
	processDone      <-chan struct{}
	settings         Settings
	start            Starter
	probe            Probe
	mu               sync.RWMutex
	running, healthy bool
	lastSuccess      time.Time
	result           ProbeResult
}

func NewSupervisor(s Settings, start Starter, probe Probe) (*Supervisor, error) {
	if !s.valid() || start == nil || probe == nil {
		return nil, errors.New("invalid supervisor settings")
	}
	return &Supervisor{settings: s, start: start, probe: probe, pause: wait}, nil
}
func (s *Supervisor) clear(running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = running
	s.processDone = nil
	s.healthy = false
	s.result = ProbeResult{}
	s.lastSuccess = time.Time{}
}
func (s *Supervisor) record(result ProbeResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = err == nil
	if err == nil {
		s.lastSuccess = time.Now()
		s.result = result
	} else {
		s.lastSuccess = time.Time{}
		s.result = ProbeResult{}
	}
}
func (s *Supervisor) Snapshot() (Info, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	running := s.running
	if s.processDone != nil {
		select {
		case <-s.processDone:
			running = false
		default:
		}
	}
	healthy := running && s.healthy && time.Since(s.lastSuccess) <= s.settings.Freshness
	result := s.result
	if !healthy {
		result = ProbeResult{}
	}
	state := "unhealthy"
	if healthy {
		state = "healthy"
	}
	return Info{result.ExitIP, result.MTU, nil, map[string]string{"state": state, "interface": "upstream0", "handshakeAge": "unavailable (no management channel)"}}, healthy
}
func (s *Supervisor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, ok := s.Snapshot()
		if !ok {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		info, _ := s.Snapshot()
		_ = json.NewEncoder(w).Encode(info)
	})
	return mux
}
func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (s *Supervisor) stop(p Process) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.settings.StopTimeout)
	defer cancel()
	return p.Stop(ctx)
}

// Run owns exactly one process. Start and Probe must honor context cancellation.
// Continuous probe failure (including startup) triggers a restart. Backoff
// grows after failures and resets only following a sustained healthy period.
func (s *Supervisor) Run(ctx context.Context) error {
	backoff := s.settings.MinBackoff
	defer s.clear(false)
	for ctx.Err() == nil {
		p, err := s.start(ctx)
		if err == nil {
			if p == nil {
				return errors.New("starter returned no process")
			}
			s.clear(true)
			s.mu.Lock()
			s.processDone = p.Done()
			s.mu.Unlock()
			stable, runErr := s.monitor(ctx, p)
			s.clear(false)
			if stopErr := s.stop(p); stopErr != nil {
				return errors.New("OpenVPN child could not be reaped")
			}
			if runErr != nil {
				return runErr
			}
			if stable {
				backoff = s.settings.MinBackoff
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if !s.pause(ctx, backoff) {
			return nil
		}
		if backoff > s.settings.MaxBackoff/2 {
			backoff = s.settings.MaxBackoff
		} else {
			backoff *= 2
		}
	}
	return nil
}
func (s *Supervisor) monitor(ctx context.Context, p Process) (bool, error) {
	ticker := time.NewTicker(s.settings.ProbeInterval)
	defer ticker.Stop()
	failureSince := time.Now()
	var healthySince time.Time
	stable := false
	// Probe immediately, then periodically; only one probe is in flight.
	for {
		select {
		case <-ctx.Done():
			return stable, nil
		case <-p.Done():
			return stable, nil
		default:
		}
		probeCtx, cancel := context.WithTimeout(ctx, s.settings.ProbeTimeout)
		type outcome struct {
			result ProbeResult
			err    error
		}
		done := make(chan outcome, 1)
		go func() { r, e := s.probe(probeCtx); done <- outcome{r, e} }()
		var o outcome
		select {
		case <-ctx.Done():
			cancel()
			return stable, nil
		case <-p.Done():
			cancel()
			return stable, nil
		case <-probeCtx.Done():
			o.err = probeCtx.Err()
		case o = <-done:
		}
		cancel()
		s.record(o.result, o.err)
		now := time.Now()
		if o.err == nil {
			failureSince = time.Time{}
			if healthySince.IsZero() {
				healthySince = now
			}
			if now.Sub(healthySince) >= s.settings.StableAfter {
				stable = true
			}
		} else {
			healthySince = time.Time{}
			if failureSince.IsZero() {
				failureSince = now
			}
			if now.Sub(failureSince) >= s.settings.FailureTimeout {
				return stable, nil
			}
		}
		select {
		case <-ctx.Done():
			return stable, nil
		case <-p.Done():
			return stable, nil
		case <-ticker.C:
		}
	}
}
