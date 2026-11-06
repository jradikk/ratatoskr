//go:build linux

package agent

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Retry only operations with no successful result or side effect on EINTR.
// Bound retries so persistent signals cannot hold reconciliation indefinitely.
func retryInterrupted(operation func() (int, error)) (int, error) {
	for attempt := 0; attempt < 16; attempt++ {
		result, err := operation()
		if !errors.Is(err, unix.EINTR) {
			return result, err
		}
	}
	return -1, unix.EINTR
}
