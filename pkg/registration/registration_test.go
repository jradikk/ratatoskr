package registration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kt "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
)

type peers struct {
	added, removed int
	ip             netip.Addr
}

func (p *peers) RegisterPeer(_ context.Context, ip netip.Addr, _ string) error {
	p.added++
	p.ip = ip
	return nil
}
func (p *peers) UnregisterPeer(_ context.Context, ip netip.Addr) error {
	p.removed++
	p.ip = ip
	return nil
}
func fixture(t *testing.T) (*Server, *peers, *corev1.Pod, *corev1.Namespace, *api.EgressGateway, *corev1.Pod) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "work", Name: "client", UID: types.UID("client-uid"), Labels: map[string]string{gatewayLabel: "vpn"}}, Spec: corev1.PodSpec{ServiceAccountName: "workload"}, Status: corev1.PodStatus{PodIP: "10.1.2.3"}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "work", Labels: map[string]string{"approved": "yes"}}}
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "vpn", UID: types.UID("gateway-uid")}, Spec: api.EgressGatewaySpec{Encryption: "wireguard", AllowedNamespaces: api.AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"approved": "yes"}}}}}
	own := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "gateway-pod", UID: types.UID("own-uid"), ResourceVersion: "1", Labels: map[string]string{identityLabel: "vpn", gatewayUIDLabel: "gateway-uid"}}, Status: corev1.PodStatus{PodIP: "10.1.2.4"}}
	kube := kt.NewClientset(own.DeepCopy())
	kube.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{Audience}, User: authv1.UserInfo{Username: "system:serviceaccount:work:workload", Extra: map[string]authv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"client"}, "authentication.kubernetes.io/pod-uid": {"client-uid"}}}}}, nil
	})
	p := &peers{}
	s := &Server{Kubernetes: kube, Reader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, ns, gw, own).Build(), Peers: p, Identity: Identity{Namespace: "operator", PodName: "gateway-pod", PodUID: "own-uid", PodIP: "10.1.2.4", GatewayName: "vpn"}}
	return s, p, pod, ns, gw, own
}
func send(s *Server) int {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	r := httptest.NewRequest(http.MethodPost, "https://gateway/v1/peers", strings.NewReader(`{"publicKey":"`+key+`"}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer synthetic-token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}
func TestRegistrationAuthorization(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*Server, *corev1.Pod, *corev1.Namespace, *api.EgressGateway, *corev1.Pod)
	}{
		{"valid", func(*Server, *corev1.Pod, *corev1.Namespace, *api.EgressGateway, *corev1.Pod) {}},
		{"wrong audience", func(s *Server, _ *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			s.Kubernetes.(*kt.Clientset).PrependReactor("create", "tokenreviews", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{"other"}}}, nil
			})
		}},
		{"missing pod claims", func(s *Server, _ *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			s.Kubernetes.(*kt.Clientset).PrependReactor("create", "tokenreviews", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{Audience}, User: authv1.UserInfo{Username: "system:serviceaccount:work:workload"}}}, nil
			})
		}},
		{"uid mismatch", func(_ *Server, p *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			p.UID = "replacement"
		}},
		{"namespace denied", func(_ *Server, _ *corev1.Pod, n *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			n.Labels["approved"] = "no"
		}},
		{"gateway mismatch", func(_ *Server, _ *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, own *corev1.Pod) {
			own.Labels[gatewayUIDLabel] = "other"
		}},
		{"deleted pod", func(_ *Server, p *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			now := metav1.Now()
			p.DeletionTimestamp = &now
			p.Finalizers = []string{"test/finalizer"}
		}},
		{"no pod IP", func(_ *Server, p *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			p.Status.PodIP = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p, pod, ns, gw, own := fixture(t)
			tc.modify(s, pod, ns, gw, own)
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = api.AddToScheme(scheme)
			s.Reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, ns, gw, own).Build()
			code := send(s)
			if tc.name == "valid" {
				if code != 201 || p.added != 1 || p.ip.String() != "10.1.2.3" {
					t.Fatalf("valid code=%d peers=%+v", code, p)
				}
			} else if code == 201 || p.added != 0 {
				t.Fatalf("unauthorized code=%d peers=%+v", code, p)
			}
		})
	}
}
func TestReconcileExpirationAndDeletion(t *testing.T) {
	s, p, pod, ns, gw, own := fixture(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	if code := send(s); code != 201 {
		t.Fatal(code)
	}
	if s.bindings["work/client"].expires.Sub(now) != 24*time.Hour {
		t.Fatal("wrong default TTL")
	}
	// A selected pod survives multiple TTL windows with periodic verification.
	for i := 0; i < 27; i++ {
		now = now.Add(time.Hour)
		if err := s.ReconcilePeers(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if p.removed != 0 || s.bindings["work/client"].expires.Before(now.Add(23*time.Hour)) {
		t.Fatal("live pod expired despite revalidation")
	}
	// API outages retain a binding until its last successful verification expires.
	s.Reader = transientReader{err: errors.New("synthetic API outage")}
	now = now.Add(23 * time.Hour)
	if err := s.ReconcilePeers(context.Background()); err != nil || p.removed != 0 {
		t.Fatalf("unexpected early expiry: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if err := s.ReconcilePeers(context.Background()); err != nil || p.removed != 1 {
		t.Fatalf("stale binding not expired: %v %+v", err, p)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	s.Reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, ns, gw, own).Build()
	if code := send(s); code != 201 {
		t.Fatal(code)
	}
	if err := s.RemoveDeletedPod(context.Background(), "work", "client", "stale"); err != nil || p.removed != 1 {
		t.Fatalf("stale event removed peer: %v", err)
	}
	if err := s.RemoveDeletedPod(context.Background(), "work", "client", "client-uid"); err != nil || p.removed != 2 {
		t.Fatalf("deletion not removed: %v", err)
	}
}

type transientReader struct{ err error }

func (t transientReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return t.err
}
func (t transientReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return t.err
}

func TestConfirmedDeletedPodFailsClosed(t *testing.T) {
	s, p, _, _, _, _ := fixture(t)
	if code := send(s); code != 201 {
		t.Fatal(code)
	}
	// A Kubernetes NotFound is evidence of deletion, not a transient API outage.
	s.Reader = transientReader{err: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "client")}
	if err := s.ReconcilePeers(context.Background()); err != nil || p.removed != 1 {
		t.Fatalf("deleted pod retained: %v", err)
	}
}
func TestReconcileRevokesChangedIdentity(t *testing.T) {
	cases := []struct {
		name   string
		change func(*corev1.Pod, *corev1.Namespace, *api.EgressGateway, *corev1.Pod)
	}{
		{"pod uid", func(p *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) { p.UID = "replacement" }},
		{"opt out", func(p *corev1.Pod, _ *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			delete(p.Labels, gatewayLabel)
		}},
		{"namespace denied", func(_ *corev1.Pod, n *corev1.Namespace, _ *api.EgressGateway, _ *corev1.Pod) {
			n.Labels["approved"] = "no"
		}},
		{"gateway changed", func(_ *corev1.Pod, _ *corev1.Namespace, g *api.EgressGateway, _ *corev1.Pod) { g.UID = "replacement" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p, pod, ns, gw, own := fixture(t)
			if code := send(s); code != 201 {
				t.Fatal(code)
			}
			tc.change(pod, ns, gw, own)
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = api.AddToScheme(scheme)
			s.Reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, ns, gw, own).Build()
			if err := s.ReconcilePeers(context.Background()); err != nil || p.removed != 1 {
				t.Fatalf("failed to revoke: %v %+v", err, p)
			}
		})
	}
}
func TestTLSAndPublication(t *testing.T) {
	c, err := NewCertificates("10.1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	conf, err := c.TLSConfig("10.1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.TLSConfig("10.1.2.5"); err == nil {
		t.Fatal("wrong IP accepted")
	}
	pemBytes := c.PublicCert()
	if bytes.Contains(pemBytes, []byte("PRIVATE KEY")) || !publicCA(pemBytes) {
		t.Fatal("CA contains private key or invalid")
	}
	b, _ := pem.Decode(pemBytes)
	root, _ := x509.ParseCertificate(b.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	for _, name := range []string{"10.1.2.4", "10.1.2.5"} {
		_, err := conf.Certificates[0].Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if (err == nil) != (name == "10.1.2.4") {
			t.Fatalf("SAN %s: %v", name, err)
		}
	}
	other, _ := NewCertificates("10.1.2.4")
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(other.PublicCert())
	if _, err := conf.Certificates[0].Leaf.Verify(x509.VerifyOptions{Roots: otherPool, DNSName: "10.1.2.4"}); err == nil {
		t.Fatal("untrusted CA accepted")
	}
	s, _, _, _, _, _ := fixture(t)
	if err := s.PublishCA(context.Background(), pemBytes); err != nil {
		t.Fatal(err)
	}
	var patched bool
	for _, action := range s.Kubernetes.(*kt.Clientset).Actions() {
		if action.Matches("update", "pods") {
			t.Fatal("publication used forbidden pods/update")
		}
		if action.Matches("patch", "pods") {
			patched = true
			patch := action.(ktesting.PatchAction)
			if patch.GetPatchType() != types.JSONPatchType || !bytes.Contains(patch.GetPatch(), []byte("/metadata/uid")) || !bytes.Contains(patch.GetPatch(), []byte("/metadata/resourceVersion")) {
				t.Fatal("patch missing identity preconditions")
			}
		}
	}
	if !patched {
		t.Fatal("publication did not patch Pod")
	}

	pod, err := s.Kubernetes.CoreV1().Pods("operator").Get(context.Background(), "gateway-pod", metav1.GetOptions{})
	if err != nil || pod.Annotations[CAAnnotation] != string(pemBytes) {
		t.Fatalf("CA publication failed: %v", err)
	}
	if net.ParseIP("10.1.2.4") == nil {
		t.Fatal("invalid fixture")
	}
}
