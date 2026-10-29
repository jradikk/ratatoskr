// Command init programs the client netns before the workload starts (M1/M2).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/version"
)

func run(configPath string, remove bool) error {
	if configPath == "" {
		return errors.New("-config is required")
	}
	f, err := os.Open(configPath) // #nosec G304 -- explicit administrator-supplied datapath configuration, not a request path.
	if err != nil {
		return fmt.Errorf("open datapath config: %w", err)
	}
	defer f.Close()
	var cfg datapath.ClientConfig
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return fmt.Errorf("decode datapath config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	backend, err := iproute.New()
	if err != nil {
		return err
	}
	defer backend.Close()
	if remove {
		return backend.RemoveClient(context.Background(), cfg)
	}
	return backend.ApplyClient(context.Background(), cfg)
}
func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "", "non-secret client datapath JSON config")
	remove := flag.Bool("remove", false, "explicitly remove steering for this pod")
	flag.Parse()
	if *showVersion {
		fmt.Println("ratatoskr-init", version.String())
		return
	}
	if err := run(*configPath, *remove); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("client datapath programming failed", "error", err)
		os.Exit(1)
	}
}
