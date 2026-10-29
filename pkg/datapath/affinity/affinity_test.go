package affinity

import (
	"net/netip"
	"slices"
	"strconv"
	"testing"
)

func ips() []netip.Addr {
	return []netip.Addr{netip.MustParseAddr("10.42.2.4"), netip.MustParseAddr("10.42.3.5"), netip.MustParseAddr("10.42.4.6")}
}

func TestSelectOneTwoThreeAndOrdering(t *testing.T) {
	all := ips()
	for n := 1; n <= len(all); n++ {
		want, err := Select("pod-uid", all[:n])
		if err != nil || !slices.Contains(all[:n], want) {
			t.Fatalf("%d endpoints: %s %v", n, want, err)
		}
		for i := 0; i < 10; i++ {
			reversed := slices.Clone(all[:n])
			slices.Reverse(reversed)
			reversed = append(reversed, all[0]) // duplicates must not skew a choice
			got, err := Select("pod-uid", reversed)
			if err != nil || got != want {
				t.Fatalf("%d endpoints, permutation %d: got %s want %s: %v", n, i, got, want, err)
			}
		}
	}
}
func TestMinimalChurnOnAdditionAndRemoval(t *testing.T) {
	all := ips()
	var selected [3]int
	for i := 0; i < 5000; i++ {
		uid := "pod-" + strconv.Itoa(i)
		one, err := Select(uid, all[:2])
		if err != nil {
			t.Fatal(err)
		}
		two, err := Select(uid, all)
		if err != nil {
			t.Fatal(err)
		}
		if one != two && two != all[2] {
			t.Fatalf("adding third endpoint moved %s to existing replica %s", one, two)
		}
		withoutFirst, err := Select(uid, all[1:])
		if err != nil {
			t.Fatal(err)
		}
		if two != all[0] && two != withoutFirst {
			t.Fatalf("removing first endpoint moved pod whose endpoint stayed healthy")
		}
		for j, ip := range all {
			if two == ip {
				selected[j]++
				break
			}
		}
	}
	for _, count := range selected {
		if count < 1000 || count > 2400 {
			t.Fatalf("uneven endpoint spread: %v", selected)
		}
	}
}
func TestWeightedDistributionAndMinimalChurn(t *testing.T) {
	all := ips()
	base := []Endpoint{{IP: all[0], Weight: 1}, {IP: all[1], Weight: 3}}
	added := append(slices.Clone(base), Endpoint{IP: all[2], Weight: 2})
	var first, second int
	for i := 0; i < 5000; i++ {
		uid := strconv.Itoa(i)
		old, err := SelectWeighted(uid, base)
		if err != nil {
			t.Fatal(err)
		}
		got, err := SelectWeighted(uid, added)
		if err != nil {
			t.Fatal(err)
		}
		if got != old && got != all[2] {
			t.Fatal("weighted addition moved existing replicas")
		}
		if old == all[0] {
			first++
		} else {
			second++
		}
	}
	if first < 950 || first > 1550 || second < 3450 || second > 4050 {
		t.Fatalf("unexpected 1:3 weighted spread %d:%d", first, second)
	}
}
func TestRejectInvalidInputFailClosed(t *testing.T) {
	all := ips()
	cases := []struct {
		uid       string
		endpoints []Endpoint
	}{
		{"", []Endpoint{{IP: all[0], Weight: 1}}},
		{"uid", nil},
		{"uid", []Endpoint{{IP: netip.Addr{}, Weight: 1}}},
		{"uid", []Endpoint{{IP: netip.MustParseAddr("2001:db8::1"), Weight: 1}}},
		{"uid", []Endpoint{{IP: netip.MustParseAddr("0.0.0.0"), Weight: 1}}},
		{"uid", []Endpoint{{IP: netip.MustParseAddr("224.1.1.1"), Weight: 1}}},
		{"uid", []Endpoint{{IP: netip.MustParseAddr("127.0.0.1"), Weight: 1}}},
		{"uid", []Endpoint{{IP: netip.MustParseAddr("169.254.1.1"), Weight: 1}}},
		{"uid", []Endpoint{{IP: all[0], Weight: 0}}},
		{"uid", []Endpoint{{IP: all[0], Weight: 1}, {IP: all[0], Weight: 2}}},
	}
	for i, tc := range cases {
		if ip, err := SelectWeighted(tc.uid, tc.endpoints); err == nil || ip.IsValid() {
			t.Fatalf("case %d accepted: %s %v", i, ip, err)
		}
	}
	if ip, err := Select("uid", nil); err == nil || ip.IsValid() {
		t.Fatal("no healthy endpoints must fail closed")
	}
}
