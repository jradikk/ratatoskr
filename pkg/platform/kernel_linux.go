//go:build linux

// Package platform verifies Linux prerequisites before network programming.
package platform

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const MinimumMajor = 5
const MinimumMinor = 10

// CheckKernel refuses kernels below 5.10 with an actionable error. Distro
// suffixes (including Ubuntu/Talos release tags) do not affect comparison.
func CheckKernel() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("read Linux kernel version: %w", err)
	}
	return ValidateKernel(unix.ByteSliceToString(uts.Release[:]))
}

func ValidateKernel(release string) error {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("unrecognized Linux kernel release %q; require >= 5.10", release)
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil || major < 0 || minor < 0 {
		return fmt.Errorf("unrecognized Linux kernel release %q; require >= 5.10", release)
	}
	if major < MinimumMajor || major == MinimumMajor && minor < MinimumMinor {
		return fmt.Errorf("linux kernel %s is below required %d.%d; upgrade the node kernel", release, MinimumMajor, MinimumMinor)
	}
	return nil
}
