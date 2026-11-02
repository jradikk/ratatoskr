package observability

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// GatewayProgramming records completed kernel datapath applications only.
// No config, identity, error text, or peer data is retained in metric labels.
// Counts are process-lifetime totals and reset on gateway process restart.
type GatewayProgramming struct {
	attempts prometheus.Counter
	errors   prometheus.Counter
	duration prometheus.Histogram
}

func NewGatewayProgramming() *GatewayProgramming {
	return &GatewayProgramming{
		attempts: prometheus.NewCounter(prometheus.CounterOpts{Name: "ratatoskr_gateway_programming_attempts_total", Help: "Completed gateway datapath application attempts since process start."}),
		errors:   prometheus.NewCounter(prometheus.CounterOpts{Name: "ratatoskr_gateway_programming_errors_total", Help: "Gateway datapath application attempts returning an error since process start."}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "ratatoskr_gateway_programming_duration_seconds", Help: "Duration of completed gateway datapath application attempts in seconds.", Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}}),
	}
}

// Observe records only a returned call. A panic propagates unchanged and is
// not counted as success (or as a completed attempt).
func (p *GatewayProgramming) Observe(apply func() error) error {
	started := time.Now()
	err := apply()
	p.attempts.Inc()
	if err != nil {
		p.errors.Inc()
	}
	p.duration.Observe(time.Since(started).Seconds())
	return err
}

func (p *GatewayProgramming) register(registry *prometheus.Registry) {
	registry.MustRegister(p.attempts, p.errors, p.duration)
}
