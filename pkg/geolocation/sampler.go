package geolocation

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// ExitSnapshot is only valid when the gateway's upstream and datapath are ready.
// An invalid snapshot immediately revokes exported coordinates.
type ExitSnapshot func() (netip.Addr, bool)
type LookupFunc func(context.Context, Provider, netip.Addr) (Result, time.Duration, error)

type Status struct {
	Provider    Provider
	ExitIP      netip.Addr
	Result      Result
	OK          bool
	LastSuccess time.Time
	Failures    uint64
}
type slot struct {
	Status
	next time.Time
}

// Sampler caches the three fixed provider samples; scraping only reads memory.
// Failures preserve a recent last-success timestamp for the same exit IP
// (up to five minutes), but set lookup_success=0 and omit coordinates.
type Sampler struct {
	mu       sync.RWMutex
	current  netip.Addr
	slots    [3]slot
	snapshot ExitSnapshot
	lookup   LookupFunc
	interval time.Duration
	now      func() time.Time
}

func NewSampler(snapshot ExitSnapshot, lookup LookupFunc, interval time.Duration) *Sampler {
	s := &Sampler{snapshot: snapshot, lookup: lookup, interval: interval, now: time.Now}
	for i, p := range Providers {
		s.slots[i].Provider = p
	}
	return s
}
func (s *Sampler) reconcile(ip netip.Addr, ready bool) {
	if !ready || !ip.Is4() || ip.IsUnspecified() {
		ip = netip.Addr{}
	}
	if s.current == ip {
		return
	}
	s.current = ip
	for i := range s.slots {
		s.slots[i].OK = false
		s.slots[i].LastSuccess = time.Time{}
		s.slots[i].Result = Result{}
		s.slots[i].ExitIP = netip.Addr{}
		// Provider quotas are source-IP-wide, not exit-IP-specific. Keep each
		// slot's cooldown across exit changes and readiness transitions.
	}
}
func (s *Sampler) Current() []Status {
	if s.snapshot == nil {
		return nil
	}
	ip, ready := s.snapshot()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcile(ip, ready)
	current := make([]Status, len(s.slots))
	for i, entry := range s.slots {
		status := entry.Status
		if s.current.Is4() {
			status.ExitIP = s.current
		}
		if s.current != ip || !s.current.IsValid() || status.LastSuccess.IsZero() || s.now().Sub(status.LastSuccess) > 5*time.Minute {
			status.OK = false
			status.LastSuccess = time.Time{}
			status.Result = Result{}
		}
		current[i] = status
	}
	return current
}

// Step is called by exactly one background runner, never by a metrics scrape.
// On exit-IP change all three previous coordinates are dropped before lookup.
func (s *Sampler) Step(ctx context.Context) {
	if s.snapshot == nil || s.lookup == nil {
		return
	}
	ip, ready := s.snapshot()
	now := s.now()
	s.mu.Lock()
	s.reconcile(ip, ready)
	active := s.current.IsValid()
	s.mu.Unlock()
	if !active {
		return
	}
	for i, p := range Providers {
		if ctx.Err() != nil {
			return
		}
		s.mu.RLock()
		due := !now.Before(s.slots[i].next)
		s.mu.RUnlock()
		if !due {
			continue
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		sample, retryAfter, err := s.lookup(requestCtx, p, ip)
		cancel()
		if err == nil && sample.IP != ip {
			err = errors.New("geolocation returned mismatched exit IP")
		}
		s.mu.Lock()
		latestIP, latestReady := s.snapshot()
		if s.current != ip || !latestReady || latestIP != ip {
			// A request reached the vendor even when exit health changed during
			// transit; consume its cooldown without publishing old coordinates.
			cooldown := s.interval
			if p == IPWhoIs && cooldown < 2*time.Minute {
				cooldown = 2 * time.Minute
			}
			if retryAfter > cooldown {
				cooldown = retryAfter
			}
			s.slots[i].next = s.now().Add(cooldown)
			s.reconcile(latestIP, latestReady)
			s.mu.Unlock()
			return
		}
		slot := &s.slots[i]
		cooldown := s.interval
		if p == IPWhoIs && cooldown < 2*time.Minute {
			cooldown = 2 * time.Minute
		} // 1000/day per public egress IP; other gateways may share that quota
		if retryAfter > cooldown {
			cooldown = retryAfter
		}
		slot.next = s.now().Add(cooldown)
		if err != nil {
			slot.Failures++
			slot.OK = false
		} else {
			slot.OK = true
			slot.Result = sample
			slot.ExitIP = ip
			slot.LastSuccess = s.now()
		}
		s.mu.Unlock()
	}
}
func (s *Sampler) Run(ctx context.Context) {
	if s.interval < time.Minute {
		return
	}
	// Delay startup to avoid an every-replica burst when an operator rolls out.
	timer := time.NewTimer(s.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.Step(ctx)
			timer.Reset(s.interval)
		}
	}
}
