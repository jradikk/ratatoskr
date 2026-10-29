//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/registration"
	"google.golang.org/grpc"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestUntrustedNamespacePaths(t *testing.T) {
	for _, v := range []string{"/var/run/netns/../net", "/var/run/netns/../../proc/1/ns/net", "/var/run/netns/sub/net", "/proc/1/ns/net", "/var/run/netns/", "var/run/netns/x"} {
		if f, err := openContainedNetns(v); err == nil {
			f.Close()
			t.Errorf("accepted %q", v)
		}
	}
	if err := os.MkdirAll("/var/run/netns", 0700); err != nil {
		t.Skipf("netns directory unavailable: %v", err)
	}
	name := "ratatoskr-test-link"
	path := filepath.Join("/var/run/netns", name)
	if err := os.Symlink("/proc/1/ns/net", path); err != nil {
		t.Skipf("cannot make symlink: %v", err)
	}
	defer os.Remove(path)
	if f, err := openContainedNetns(path); err == nil {
		f.Close()
		t.Fatal("followed symlink")
	}
}

type fakeCRI struct {
	cri.RuntimeServiceClient
	item     *cri.PodSandbox
	response *cri.PodSandboxStatusResponse
}

func (f fakeCRI) ListPodSandbox(context.Context, *cri.ListPodSandboxRequest, ...grpc.CallOption) (*cri.ListPodSandboxResponse, error) {
	return &cri.ListPodSandboxResponse{Items: []*cri.PodSandbox{f.item}}, nil
}
func (f fakeCRI) PodSandboxStatus(context.Context, *cri.PodSandboxStatusRequest, ...grpc.CallOption) (*cri.PodSandboxStatusResponse, error) {
	return f.response, nil
}
func TestSandboxUIDMismatch(t *testing.T) {
	md := &cri.PodSandboxMetadata{Name: "p", Namespace: "ns", Uid: "other"}
	labels := map[string]string{"io.kubernetes.pod.uid": "wanted"}
	f := fakeCRI{item: &cri.PodSandbox{Id: "s", Metadata: md, Labels: labels, State: cri.PodSandboxState_SANDBOX_READY}, response: &cri.PodSandboxStatusResponse{Status: &cri.PodSandboxStatus{Id: "s", Metadata: md, Labels: labels, State: cri.PodSandboxState_SANDBOX_READY}, Info: map[string]string{"info": `{"pid":1}`}}}
	if n, err := Sandbox(context.Background(), f, "ns", "p", "wanted", "10.1.0.2"); err == nil {
		n.Close()
		t.Fatal("accepted mismatched UID")
	}
	f.item.Metadata.Uid = "wanted"
	if n, err := Sandbox(context.Background(), f, "ns", "p", "wanted", "10.1.0.2"); err == nil {
		n.Close()
		t.Fatal("accepted mismatched status UID")
	}
}
func TestHostNamespaceRejectedAndUnchanged(t *testing.T) {
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	called := false
	if err := InNamespace(f, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("entered host namespace")
	}
}
func TestConfigFailClosedAndEndpointHash(t *testing.T) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: types.UID("uid"), Labels: map[string]string{GatewayLabel: "g"}}, Spec: corev1.PodSpec{NodeName: "node"}, Status: corev1.PodStatus{PodIP: "10.1.0.2"}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "operator", Generation: 1}, Spec: api.EgressGatewaySpec{AllowedNamespaces: api.AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{}}}, Status: api.EgressGatewayStatus{ObservedGeneration: 1, GatewayID: 10, MTU: api.GatewayMTUStatus{EffectiveMTU: 1400}}}
	c, err := Config(p, ns, gw, nil, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint.IsValid() {
		t.Fatal("unexpected healthy endpoint")
	}
	old := Hash(c)
	gw.Status.Endpoints = []api.GatewayEndpoint{{PodIP: "10.2.0.3", UpstreamHealthy: true}}
	c, err = Config(p, ns, gw, nil, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != netip.MustParseAddr("10.2.0.3") || Hash(c) == old {
		t.Fatal("endpoint update not reflected")
	}
	gw.Spec.Encryption = "wireguard"
	if _, err = Config(p, ns, gw, nil, "operator"); err == nil || !strings.Contains(err.Error(), "public identity") {
		t.Fatal("unauthenticated endpoint accepted")
	}
	gw.Status.Endpoints[0].WireguardPublicKey = "invalid"
	gw.Status.Endpoints[0].RegistrationCACert = "invalid"
	c, err = Config(p, ns, gw, nil, "operator")
	if err != nil || c.Encryption != "wireguard" {
		t.Fatalf("encrypted config: %v", err)
	}
	raw, _ := json.Marshal(datapath.ClientConfig{PodIP: c.PodIP})
	if len(raw) == 0 {
		t.Fatal("empty config encoding")
	}
}

type captureIssuer struct {
	request *authv1.TokenRequest
	ns, sa  string
}

func (f *captureIssuer) CreateToken(_ context.Context, ns, sa string, req *authv1.TokenRequest, _ metav1.CreateOptions) (*authv1.TokenRequest, error) {
	f.request = req
	f.ns = ns
	f.sa = sa
	return &authv1.TokenRequest{Status: authv1.TokenRequestStatus{Token: "in-memory-only"}}, nil
}
func TestPodBoundTokenRequest(t *testing.T) {
	issuer := &captureIssuer{}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p", UID: types.UID("uid")}, Spec: corev1.PodSpec{ServiceAccountName: "sa"}}
	token, err := podBoundToken(context.Background(), issuer, p)
	if err != nil || token != "in-memory-only" {
		t.Fatalf("token request failed: %v", err)
	}
	ref := issuer.request.Spec.BoundObjectRef
	if issuer.ns != "ns" || issuer.sa != "sa" || ref == nil || ref.Kind != "Pod" || ref.APIVersion != "v1" || ref.Name != "p" || ref.UID != "uid" || len(issuer.request.Spec.Audiences) != 1 || issuer.request.Spec.Audiences[0] != registration.Audience {
		t.Fatal("token not bound to exact pod and audience")
	}
	p.Spec.ServiceAccountName = ""
	if _, err := podBoundToken(context.Background(), issuer, p); err == nil {
		t.Fatal("unbound token allowed")
	}
}
