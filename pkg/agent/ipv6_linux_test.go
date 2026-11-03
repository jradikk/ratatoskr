//go:build linux

package agent

import "testing"

func TestIPv6GuardAndQuarantineHaveSeparateTables(t *testing.T) {
	if ipv6GuardTable == quarantineTable || ipv6GuardTable == "" || quarantineTable == "" {
		t.Fatal("selected IPv6 guard must not imply authorization quarantine")
	}
}
