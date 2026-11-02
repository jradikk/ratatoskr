package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

const appliedAckPath = "/var/run/ratatoskr/applied-ack.json"
const appliedAckTimeout = 120 * time.Second
const appliedAckInterval = 250 * time.Millisecond

type gatewayAppliedAck struct {
	WorkloadUID   string `json:"workloadUID"`
	WorkloadPodIP string `json:"workloadPodIP"`
	GatewayUID    string `json:"gatewayUID"`
	GatewayID     uint32 `json:"gatewayID"`
	GatewayPodUID string `json:"gatewayPodUID"`
	GatewayPodIP  string `json:"gatewayPodIP"`
	ConfigHash    string `json:"configHash"`
}

func validateAppliedAck(raw []byte, c datapath.ClientConfig) error {
	if len(raw) == 0 {
		return errors.New("applied gateway ack pending")
	}
	if len(raw) > 4096 {
		return errors.New("applied gateway ack exceeds size limit")
	}
	var ack gatewayAppliedAck
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&ack); err != nil {
		return errors.New("applied gateway ack invalid")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("applied gateway ack has trailing data")
	}
	if c.Identity.UID == "" || ack.WorkloadUID != c.Identity.UID || ack.WorkloadPodIP != c.PodIP.String() || ack.GatewayID != c.GatewayID || ack.GatewayPodIP != c.Endpoint.String() || ack.GatewayUID == "" || ack.GatewayPodUID == "" || len(ack.ConfigHash) != 64 || !lowerHex(ack.ConfigHash) {
		return errors.New("applied gateway ack does not match selected workload and endpoint")
	}
	ip, err := netip.ParseAddr(ack.GatewayPodIP)
	if err != nil || !ip.Is4() || !ip.IsValid() {
		return errors.New("applied gateway PodIP is invalid")
	}
	return nil
}
func lowerHex(s string) bool {
	for _, v := range s {
		if (v < '0' || v > '9') && (v < 'a' || v > 'f') {
			return false
		}
	}
	return true
}
func waitAppliedAck(ctx context.Context, c datapath.ClientConfig, read func() ([]byte, error), interval time.Duration) error {
	if read == nil || interval <= 0 {
		return errors.New("applied gateway ack reader unavailable")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		raw, err := read()
		if err == nil && validateAppliedAck(raw, c) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for applied gateway ack: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
func readProjectedAck() ([]byte, error) { return os.ReadFile(appliedAckPath) }
