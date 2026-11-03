package observability

import "testing"

func TestMetricsAddressAndEnableValidation(t *testing.T) {
	for _, tc := range []struct {
		enabled, bind, want string
		fail                bool
	}{
		{"", "", "0.0.0.0:8080", false},
		{"true", "127.0.0.1:9999", "127.0.0.1:9999", false},
		{"false", "", "0", false},
		{"false", "invalid", "0", false},
		{"true", "0", "", true},
		{"unknown", "", "", true},
	} {
		got, err := ManagerMetricsBindAddress(tc.enabled, tc.bind, "0.0.0.0:8080")
		if got != tc.want || (err != nil) != tc.fail {
			t.Fatalf("manager metrics enabled=%q bind=%q: got %q error %v, want %q fail %t", tc.enabled, tc.bind, got, err, tc.want, tc.fail)
		}
	}
	for _, tc := range []struct {
		value, want string
		fail        bool
	}{
		{"", "0.0.0.0:9902", false},
		{"127.0.0.1:9902", "127.0.0.1:9902", false},
		{"0.0.0.0:9902", "0.0.0.0:9902", false},
		{"[::]:9902", "", true},
		{"gateway.example:9902", "", true},
		{":9902", "", true},
		{"0.0.0.0:0", "", true},
		{"0.0.0.0:65536", "", true},
		{"0.0.0.0:+9902", "", true},
		{"0.0.0.0:09902", "", true},
		{"0", "", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := MetricsBindAddress(tc.value, "0.0.0.0:9902")
			if got != tc.want || (err != nil) != tc.fail {
				t.Fatalf("address=%q error=%v, want=%q fail=%t", got, err, tc.want, tc.fail)
			}
		})
	}
	for _, tc := range []struct {
		value      string
		want, fail bool
	}{
		{"", true, false}, {"true", true, false}, {"false", false, false},
		{"False", false, true}, {"0", false, true}, {"none", false, true},
	} {
		got, err := MetricsEnabled(tc.value)
		if got != tc.want || (err != nil) != tc.fail {
			t.Fatalf("enabled %q got=%t error=%v", tc.value, got, err)
		}
	}
}
