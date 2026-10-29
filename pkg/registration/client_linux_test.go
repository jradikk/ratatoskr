//go:build linux

package registration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedRegistrationTLSAndBearer(t *testing.T) {
	cert, err := NewCertificates("10.42.2.4")
	if err != nil {
		t.Fatal(err)
	}
	config, err := cert.TLSConfig("10.42.2.4")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.URL.Path != "/v1/peers" || r.Method != http.MethodPost || r.TLS == nil || r.Header.Get("Authorization") == "" {
			t.Error("registration request missing authenticated envelope")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	leaf, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	// httptest installs its own localhost cert when Certificates is empty;
	// explicitly present the gateway's in-memory IP-SAN serving identity.
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: config.GetCertificate, Certificates: []tls.Certificate{*leaf}}
	server.StartTLS()
	defer server.Close()
	path := filepath.Join(t.TempDir(), "projected-token")
	// This synthetic local test fixture is not a Kubernetes token or credential.
	if err := os.WriteFile(path, []byte(strings.Repeat("A", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	request := ClientRequest{GatewayPodIP: netip.MustParseAddr("10.42.2.4"), RegistrationCACert: cert.PublicCert(), ClientPublicKey: key, ProjectedTokenPath: path, BypassMark: 0x00200000}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	if err := registerClient(context.Background(), request, dial); err != nil {
		t.Fatal(err)
	}
	request.AgentHostNetwork = true
	request.BypassMark = 0
	request.ProjectedTokenPath = ""
	request.TokenProvider = func(context.Context) (string, error) { return strings.Repeat("A", 64), nil }
	if err := registerClient(context.Background(), request, dial); err != nil {
		t.Fatalf("agent in-memory token registration failed: %v", err)
	}
	request.TokenProvider = nil
	if err := registerClient(context.Background(), request, dial); err == nil {
		t.Fatal("agent without token provider accepted")
	}
	request.AgentHostNetwork = false
	request.TokenProvider = nil
	request.BypassMark = 0x00200000
	request.ProjectedTokenPath = path
	if seen != 2 {
		t.Fatal("expected exactly two authenticated requests")
	}
	request.GatewayPodIP = netip.MustParseAddr("10.42.2.5")
	if err := registerClient(context.Background(), request, dial); err == nil {
		t.Fatal("wrong gateway IP SAN accepted")
	}
	request.GatewayPodIP = netip.MustParseAddr("10.42.2.4")
	other, err := NewCertificates("10.42.2.4")
	if err != nil {
		t.Fatal(err)
	}
	request.RegistrationCACert = other.PublicCert()
	if err := registerClient(context.Background(), request, dial); err == nil {
		t.Fatal("wrong gateway CA accepted")
	}
	request.RegistrationCACert = cert.PublicCert()
	request.BypassMark = 0
	if err := registerClient(context.Background(), request, dial); err == nil {
		t.Fatal("unmarked bootstrap attempted fallback")
	}
}
