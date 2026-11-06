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

// retryInterruptedErr is only for operations whose EINTR outcome can be
// retried without an ambiguous side effect (e.g. stat on an already-pinned FD).
func retryInterruptedErr(operation func() error) error {
	_, err := retryInterrupted(func() (int, error) { return 0, operation() })
	return err
}
