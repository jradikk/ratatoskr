package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// AgentProgramming records only completed client netns programming calls.
// Operations have a fixed vocabulary; no Pod, namespace, gateway, route,
// credential, error text, or kernel process identity is retained as a label.
// Counts reset with the agent process and are not a success/health gauge.
type AgentProgramming struct {
	attempts *prometheus.CounterVec
	errors   *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

const (
	AgentUsable  = "usable"
	AgentClosed  = "closed"
	AgentCleanup = "cleanup"
)

var agentOperations = [...]string{AgentUsable, AgentClosed, AgentCleanup}

func NewAgentProgramming() *AgentProgramming {
	p := &AgentProgramming{
		attempts: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ratatoskr_agent_programming_attempts_total", Help: "Completed agent client datapath programming attempts since process start."}, []string{"operation"}),
		errors:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ratatoskr_agent_programming_errors_total", Help: "Completed agent client datapath programming attempts returning an error since process start."}, []string{"operation"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "ratatoskr_agent_programming_duration_seconds", Help: "Duration of completed agent client datapath programming attempts in seconds.", Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}}, []string{"operation"}),
	}
	for _, operation := range agentOperations {
		p.attempts.WithLabelValues(operation)
		p.errors.WithLabelValues(operation)
		p.duration.WithLabelValues(operation)
	}
	return p
}

// Observe accepts only a fixed operation. A panic propagates without counting
// it as a completed attempt; this deliberately does not time CRI/API checks,
// token issuance, peer registration, or Pod annotation patches.
func (p *AgentProgramming) Observe(operation string, apply func() error) error {
	switch operation {
	case AgentUsable, AgentClosed, AgentCleanup:
	default:
		panic("unsupported agent programming operation")
	}
	started := time.Now()
	err := apply()
	p.attempts.WithLabelValues(operation).Inc()
	if err != nil {
		p.errors.WithLabelValues(operation).Inc()
	}
	p.duration.WithLabelValues(operation).Observe(time.Since(started).Seconds())
	return err
}

// AgentHandler exposes only the dedicated private registry; Go/process and
// unrelated gateway/WireGuard metrics must never leak through this endpoint.
func AgentHandler(programming *AgentProgramming) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(programming.attempts, programming.errors, programming.duration)
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}
