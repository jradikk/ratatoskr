//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/skaldhall/ratatoskr/plugins/upstream/openvpn"
)

func main() {
	if err := run(); err != nil {
		// All library runtime errors are fixed strings. Do not print flags, URLs,
		// process output, environment, credentials or config data here.
		fmt.Fprintln(os.Stderr, "OpenVPN upstream stopped; check mount, TUN access and probe settings")
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("openvpn-upstream", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	secrets := flags.String("secret-dir", "/etc/ratatoskr/upstream", "read-only Secret mount")
	runtimeDir := flags.String("runtime-dir", "/run/ratatoskr", "private ephemeral runtime directory")
	endpoint := flags.String("probe-url", openvpn.DefaultProbeURL, "optional HTTP(S) endpoint override returning plain exit IPv4")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return openvpn.ErrConfig
	}
	probe, err := openvpn.NewHTTPProbe(*endpoint)
	if err != nil {
		return err
	}
	if err = openvpn.EnsureTUN(); err != nil {
		return err
	}
	if err = os.MkdirAll(*runtimeDir, 0700); err != nil {
		return err
	}
	supervisor, err := openvpn.NewSupervisor(openvpn.DefaultSettings(), openvpn.CommandStarter("/usr/sbin/openvpn", *secrets, *runtimeDir), probe)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:9901")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: supervisor.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener); cancel() }()
	err = supervisor.Run(ctx)
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	serveErr := <-served
	if err != nil {
		return err
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
