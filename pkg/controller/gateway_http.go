package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// One bounded pool is shared across reconciles. Creating a fresh transport per
// probe retains idle sockets indefinitely and can exhaust local source ports.
var defaultGatewayHTTPClient = newGatewayHTTPClient()

func newGatewayHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy:        nil,
			DialContext:  (&net.Dialer{Timeout: time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns: 64, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 2,
			IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (r *GatewayReconciler) gatewayHTTPClient() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return defaultGatewayHTTPClient
}

// Read the whole bounded response so successful probes reuse their connection.
// Body contents never become errors, logs or Events.
func decodeGatewayInfo(resp *http.Response, info *gatewayInfo) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil {
		return err
	}
	if len(body) > 4096 {
		return errors.New("gateway info response too large")
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("gateway info HTTP status not OK")
	}
	if err := json.Unmarshal(body, info); err != nil {
		return errors.New("gateway info response invalid JSON")
	}
	return nil
}

type gatewayHealthLogState struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func gatewayProbeAdvice(err error) (string, string) {
	switch {
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "LocalAddressUnavailable", "Controller could not allocate a local source address; inspect its TCP socket/ephemeral-port usage and Pod networking."
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return "LocalSocketLimit", "Controller reached an open-file/socket limit; inspect its file descriptors and connection counts."
	case errors.Is(err, syscall.ECONNREFUSED):
		return "ConnectionRefused", "Gateway health port TCP/9900 refused the connection; check the gateway listener and Pod IP."
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "NetworkUnreachable", "Controller cannot route to the gateway Pod; inspect controller Pod routes and CNI connectivity."
	case errors.Is(err, context.DeadlineExceeded):
		return "Timeout", "Gateway health request timed out; check controller-to-gateway TCP/9900 connectivity and gateway response latency."
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "Timeout", "Gateway health request timed out; check controller-to-gateway TCP/9900 connectivity and gateway response latency."
	}
	return "ProbeFailed", "Controller could not obtain valid gateway health information; check TCP/9900 connectivity and the gateway /info response."
}

func (r *GatewayReconciler) reportGatewayProbe(ctx context.Context, podName, podUID string, err error) {
	r.healthLogs.mu.Lock()
	defer r.healthLogs.mu.Unlock()
	if err == nil {
		delete(r.healthLogs.last, podUID)
		return
	}
	if r.healthLogs.last == nil {
		r.healthLogs.last = make(map[string]time.Time)
	}
	if time.Since(r.healthLogs.last[podUID]) < time.Minute {
		return
	}
	if len(r.healthLogs.last) >= 1024 {
		clear(r.healthLogs.last)
	}
	r.healthLogs.last[podUID] = time.Now()
	category, advice := gatewayProbeAdvice(err)
	log.FromContext(ctx).Info("gateway health observation failed", "gatewayPod", podName, "category", category, "advice", advice)
}
