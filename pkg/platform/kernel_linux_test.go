//go:build linux

package platform

import (
	"strings"
	"testing"
)

func TestValidateKernel(t *testing.T) {
	for _, tc := range []struct {
		release string
		wantErr bool
	}{{"5.4.0-1", true}, {"5.9.22", true}, {"5.10.0-talos", false}, {"5.15.0-aws", false}, {"6.1.0", false}, {"7.0.0-28-generic", false}, {"4.19.300", true}, {"garbage", true}, {"5.foo", true}, {"", true}} {
		t.Run(tc.release, func(t *testing.T) {
			err := ValidateKernel(tc.release)
			if (err != nil) != tc.wantErr {
				t.Fatalf("kernel %s: error=%v wantErr=%t", tc.release, err, tc.wantErr)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "5.10") {
				t.Fatalf("missing required version: %v", err)
			}
		})
	}
}
func TestLiveKernelBaseline(t *testing.T) {
	if err := CheckKernel(); err != nil {
		t.Fatal(err)
	}
}
