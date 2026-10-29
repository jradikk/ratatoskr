//go:build linux

package registration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ClientRequest contains only public gateway identity and the path of a
// projected, audience-specific Pod-bound token. It never returns or logs the
// token; errors are deliberately generic.
type ClientRequest struct {
	GatewayPodIP       netip.Addr
	RegistrationCACert []byte
	ClientPublicKey    string
	ProjectedTokenPath string
	BypassMark         uint32
}

// RegisterClient authenticates the gateway by the public CA published through
// the trusted Kubernetes API, then presents a Pod-bound bearer token over
// TLS 1.3. The control socket is bound to eth0 and marked to bypass the WG
// endpoint route; no proxy, redirect, DNS lookup or unbound fallback exists.
func RegisterClient(ctx context.Context, r ClientRequest) error {
	return registerClient(ctx, r, nil)
}
func registerClient(ctx context.Context, r ClientRequest, dialOverride func(context.Context, string, string) (net.Conn, error)) error {
	if !r.GatewayPodIP.Is4() || r.GatewayPodIP.IsUnspecified() || r.GatewayPodIP.IsLoopback() || r.GatewayPodIP.IsMulticast() || r.BypassMark == 0 || r.ProjectedTokenPath == "" || len(r.RegistrationCACert) > 4096 {
		return errors.New("invalid gateway registration identity")
	}
	if data, err := base64.StdEncoding.Strict().DecodeString(r.ClientPublicKey); err != nil || len(data) != 32 {
		return errors.New("invalid client public key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(r.RegistrationCACert) {
		return errors.New("invalid gateway registration CA")
	}
	f, err := os.Open(r.ProjectedTokenPath) // #nosec G304 -- fixed projected Pod-bound ServiceAccount token path supplied by injected init.
	if err != nil {
		return errors.New("projected registration token unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 {
		return errors.New("invalid projected registration token")
	}
	tokenBytes, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err != nil {
		return errors.New("read projected token failed")
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" || len(token) > 16<<10 || strings.ContainsAny(token, " \r\n\t") {
		return errors.New("projected token invalid")
	}
	body, err := json.Marshal(struct {
		PublicKey string `json:"publicKey"`
	}{r.ClientPublicKey})
	if err != nil {
		return errors.New("registration encoding failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(r.GatewayPodIP.String(), "9443")+"/v1/peers", bytes.NewReader(body))
	if err != nil {
		return errors.New("registration request failed")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "eth0")
			if sockErr == nil {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(r.BypassMark))
			}
		}); err != nil {
			return err
		}
		return sockErr
	}}
	dial := dialer.DialContext
	if dialOverride != nil {
		dial = dialOverride
	} // test-only injection; public RegisterClient always uses marked/bound dialer.
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: r.GatewayPodIP.String(), MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("registration redirects forbidden") }}
	resp, err := client.Do(request)
	if err != nil {
		return errors.New("gateway registration unavailable or TLS identity invalid")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusCreated {
		return errors.New("gateway peer registration rejected")
	}
	return nil
}
