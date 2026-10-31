package advanced_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/skaldhall/ratatoskr/pkg/datapath/affinity"
)

// Offline contract for 1-3 healthy replicas; this is NOT a gateway rollout or
// evidence that existing connections survive a change of VPN exit identity.
func TestReplicaAffinityAndFailoverContract(t *testing.T) {
	a := netip.MustParseAddr("10.42.2.4")
	b := netip.MustParseAddr("10.42.2.5")
	c := netip.MustParseAddr("10.42.2.6")
	pool := []netip.Addr{a, b, c}
	if _, err := affinity.Select("client-0", nil); err == nil {
		t.Fatal("no healthy gateway must not select baseline routing")
	}
	for replicas := 1; replicas <= 3; replicas++ {
		active := pool[:replicas]
		seen := map[netip.Addr]bool{}
		for i := 0; i < 400; i++ {
			uid := fmt.Sprintf("client-%d", i)
			chosen, err := affinity.Select(uid, active)
			if err != nil || !contains(active, chosen) {
				t.Fatalf("%d replicas selected %s: %v", replicas, chosen, err)
			}
			reversed := append([]netip.Addr(nil), active...)
			for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
				reversed[left], reversed[right] = reversed[right], reversed[left]
			}
			again, err := affinity.Select(uid, reversed)
			if err != nil || again != chosen {
				t.Fatalf("selection changed on endpoint reordering: %s -> %s: %v", chosen, again, err)
			}
			seen[chosen] = true
			// Removing a fixed failed replica must leave every unaffected
			// client's choice unchanged (minimal churn).
			if replicas == 3 {
				withoutA := []netip.Addr{b, c}
				remaining, err := affinity.Select(uid, withoutA)
				if err != nil || !contains(withoutA, remaining) {
					t.Fatalf("failed replica remained selectable: %s: %v", remaining, err)
				}
				if chosen != a && remaining != chosen {
					t.Fatalf("unaffected client %s moved from %s to %s", uid, chosen, remaining)
				}
			}
			if replicas == 1 && chosen != a {
				t.Fatal("single replica affinity changed")
			}
			if replicas == 1 {
				continue
			}
			without := make([]netip.Addr, 0, replicas-1)
			for _, candidate := range active {
				if candidate != chosen {
					without = append(without, candidate)
				}
			}
			failover, err := affinity.Select(uid, without)
			if err != nil || !contains(without, failover) || failover == chosen {
				t.Fatalf("failed replica selected after removal: %s: %v", failover, err)
			}
			// Only NEW connections can be attributed to the new replica/exit.
			// Existing-flow continuity is not asserted, and must not be inferred.
		}
		if len(seen) != replicas {
			t.Fatalf("only %d of %d replicas selected", len(seen), replicas)
		}
	}
}

func contains(endpoints []netip.Addr, ip netip.Addr) bool {
	for _, endpoint := range endpoints {
		if ip == endpoint {
			return true
		}
	}
	return false
}
