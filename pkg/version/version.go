// Package version exposes build metadata injected via -ldflags.
package version

import "runtime"

// Set at build time: -X github.com/skaldhall/ratatoskr/pkg/version.Version=...
var (
	Version = "dev"
	Commit  = "unknown"
)

// String returns a human-readable build description.
func String() string {
	return Version + " (" + Commit + ", " + runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
