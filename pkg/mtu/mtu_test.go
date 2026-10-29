package mtu

import (
	"strings"
	"testing"
)

func TestCompute(t *testing.T) {
	tests := []struct {
		name    string
		p       Params
		want    Result
		wantErr string
	}{
		{
			name: "flannel vxlan, no encryption, iproute (no TLVs)",
			p:    Params{PodMTU: 1450, Underlay: IPv4, Encryption: EncryptionNone},
			want: Result{GeneveMTU: 1400, EffectiveMTU: 1400, MSS: 1360},
		},
		{
			name: "plain 1500, ebpf with 12 bytes of TLVs",
			p:    Params{PodMTU: 1500, Underlay: IPv4, TLVBytes: 12},
			want: Result{GeneveMTU: 1438, EffectiveMTU: 1438, MSS: 1398},
		},
		{
			name: "wireguard over 1450 pod MTU",
			p:    Params{PodMTU: 1450, Underlay: IPv4, Encryption: EncryptionWireGuard},
			want: Result{WireGuardMTU: 1390, GeneveMTU: 1340, EffectiveMTU: 1340, MSS: 1300},
		},
		{
			name: "upstream tunnel is the bottleneck",
			p:    Params{PodMTU: 1500, Underlay: IPv4, UpstreamMTU: 1380},
			want: Result{GeneveMTU: 1450, EffectiveMTU: 1380, MSS: 1340},
		},
		{
			name: "upstream larger than geneve is ignored",
			p:    Params{PodMTU: 1450, Underlay: IPv4, UpstreamMTU: 1500},
			want: Result{GeneveMTU: 1400, EffectiveMTU: 1400, MSS: 1360},
		},
		{
			name: "ipv6 underlay, wireguard",
			p:    Params{PodMTU: 1500, Underlay: IPv6, Encryption: EncryptionWireGuard},
			want: Result{WireGuardMTU: 1420, GeneveMTU: 1370, EffectiveMTU: 1370, MSS: 1330},
		},
		{
			name: "jumbo frames",
			p:    Params{PodMTU: 9001, Underlay: IPv4, Encryption: EncryptionWireGuard, TLVBytes: 12},
			want: Result{WireGuardMTU: 8941, GeneveMTU: 8879, EffectiveMTU: 8879, MSS: 8839},
		},
		{
			name: "below ipv6 minimum warns",
			p:    Params{PodMTU: 1370, Underlay: IPv4, Encryption: EncryptionWireGuard, TLVBytes: 12},
			want: Result{WireGuardMTU: 1310, GeneveMTU: 1248, EffectiveMTU: 1248, MSS: 1208,
				Warnings: []string{"effective MTU 1248 is below the IPv6 minimum of 1280"}},
		},
		{name: "too small", p: Params{PodMTU: 600, Underlay: IPv4}, wantErr: "below the minimum"},
		{name: "bad tlv alignment", p: Params{PodMTU: 1500, Underlay: IPv4, TLVBytes: 6}, wantErr: "multiple of 4"},
		{name: "tlv too long", p: Params{PodMTU: 1500, Underlay: IPv4, TLVBytes: 256}, wantErr: "multiple of 4"},
		{name: "zero pod mtu", p: Params{Underlay: IPv4}, wantErr: "positive"},
		{name: "unknown family", p: Params{PodMTU: 1500}, wantErr: "family"},
		{name: "unknown encryption", p: Params{PodMTU: 1500, Underlay: IPv4, Encryption: "ipsec"}, wantErr: "unknown encryption"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Compute(tc.p)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.WireGuardMTU != tc.want.WireGuardMTU || got.GeneveMTU != tc.want.GeneveMTU ||
				got.EffectiveMTU != tc.want.EffectiveMTU || got.MSS != tc.want.MSS ||
				strings.Join(got.Warnings, ";") != strings.Join(tc.want.Warnings, ";") {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestOverheads(t *testing.T) {
	if got := GeneveOverhead(IPv4, 0); got != 50 {
		t.Errorf("GENEVE/IPv4 overhead = %d, want 50", got)
	}
	if got := GeneveOverhead(IPv6, 8); got != 78 {
		t.Errorf("GENEVE/IPv6 overhead with 8B TLV = %d, want 78", got)
	}
	if got := WireGuardOverhead(IPv4); got != 60 {
		t.Errorf("WireGuard/IPv4 overhead = %d, want 60", got)
	}
	if got := WireGuardOverhead(IPv6); got != 80 {
		t.Errorf("WireGuard/IPv6 overhead = %d, want 80", got)
	}
}
