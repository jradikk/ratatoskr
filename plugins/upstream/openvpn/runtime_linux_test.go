//go:build linux

package openvpn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fakeRawConn struct{ err error }

func (f fakeRawConn) Control(fn func(uintptr)) error {
	if f.err != nil {
		return f.err
	}
	fn(123)
	return nil
}
func (fakeRawConn) Read(func(uintptr) bool) error  { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error { return nil }
func TestSocketControlsFailClosed(t *testing.T) {
	var calls []string
	bind := func(fd int) error {
		if fd != 123 {
			t.Fatal("wrong descriptor")
		}
		calls = append(calls, "bind")
		return nil
	}
	mark := func(fd int) error { calls = append(calls, "mark"); return nil }
	if err := socketControl(fakeRawConn{}, bind, mark); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "bind,mark" || ProbeMark != 0x00100000 || ProbeMarkMask != 0x00f00000 || ProbeRoutingTable != 100 {
		t.Fatal("socket routing contract changed")
	}
	fail := errors.New("synthetic socket denial")
	calls = nil
	if err := socketControl(fakeRawConn{}, func(int) error { return fail }, mark); !errors.Is(err, fail) || len(calls) != 0 {
		t.Fatal("bind denial did not fail closed")
	}
	if err := socketControl(fakeRawConn{}, bind, func(int) error { return fail }); !errors.Is(err, fail) {
		t.Fatal("mark denial did not fail closed")
	}
	if err := socketControl(fakeRawConn{fail}, bind, mark); !errors.Is(err, fail) {
		t.Fatal("raw control error ignored")
	}
}

var _ syscall.RawConn = fakeRawConn{}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func upInterface(name string) (*net.Interface, error) {
	if name != Interface {
		return nil, errors.New("wrong interface")
	}
	return &net.Interface{MTU: 1400, Flags: net.FlagUp}, nil
}
func TestHTTPProbeWithoutNetwork(t *testing.T) {
	const endpoint = "http://192.0.2.1/exit"
	cases := []struct {
		name, body string
		status     int
		wantOK     bool
	}{
		{"valid", "203.0.113.42\n", 200, true},
		{"invalid", "not an IP", 200, false}, {"loopback", "127.0.0.1", 200, false},
		{"ipv6", "2001:db8::1", 200, false}, {"too-big", strings.Repeat("x", 65), 200, false},
		{"status", "203.0.113.42", 500, false}, {"unspecified", "0.0.0.0", 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := newHTTPProbe(endpoint, upInterface, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.String() != endpoint {
					t.Fatal("unexpected probe request")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			result, err := probe(context.Background())
			if (err == nil) != tc.wantOK {
				t.Fatal("unexpected probe outcome")
			}
			if tc.wantOK && (result.ExitIP != "203.0.113.42" || result.MTU != 1400) {
				t.Fatal("wrong exit IP or MTU")
			}
		})
	}
	called := false
	probe, err := newHTTPProbe(endpoint, func(string) (*net.Interface, error) { return &net.Interface{}, nil }, roundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New("unexpected") }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = probe(context.Background()); err == nil || called {
		t.Fatal("down interface reached network")
	}
	probe, err = newHTTPProbe(endpoint, upInterface, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://192.0.2.2/exit"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = probe(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
	probe, err = newHTTPProbe(endpoint, upInterface, roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = probe(ctx); err == nil {
		t.Fatal("canceled probe accepted")
	}
}
func TestProbeURLValidation(t *testing.T) {
	for _, endpoint := range []string{"", "ftp://192.0.2.1", "http://example.invalid/exit", "http://127.0.0.1", "http://0.0.0.0", "http://224.0.0.1", "http://[2001:db8::1]", "http://user:placeholder@192.0.2.1", "http://192.0.2.1/#fragment"} {
		if _, err := NewHTTPProbe(endpoint); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, endpoint := range []string{"http://192.0.2.1/exit", "https://192.0.2.1:8443/exit"} {
		if _, err := NewHTTPProbe(endpoint); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCommandStarterRejectsAndCleansRuntimeCopy(t *testing.T) {
	secret := t.TempDir()
	runtime := t.TempDir()
	// Only a synthetic transport directive. No real VPN profile or credentials.
	if err := os.WriteFile(filepath.Join(secret, "client.ovpn"), []byte("client\nremote vpn.example.invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	start := CommandStarter("/nonexistent-synthetic-openvpn", secret, runtime)
	if _, err := start(context.Background()); err == nil {
		t.Fatal("missing process executable accepted")
	}
	entries, err := os.ReadDir(runtime)
	if err != nil || len(entries) != 0 {
		t.Fatal("runtime config not removed on failed start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled start accepted")
	}
	if err := os.WriteFile(filepath.Join(secret, "client.ovpn"), []byte("plugin /never/load\nconfig escape.ovpn\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := start(context.Background()); !errors.Is(err, ErrConfig) {
		t.Fatal("unsafe configuration did not fail before process launch")
	}
	if err := os.Remove(filepath.Join(secret, "client.ovpn")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("SYNTHETIC"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(secret, "client.ovpn")); err != nil {
		t.Fatal(err)
	}
	if _, err := start(context.Background()); !errors.Is(err, ErrConfig) {
		t.Fatal("outside config symlink accepted")
	}
}
