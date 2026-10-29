// Package registration authenticates pod-bound gateway registrations and maintains
// short-lived bindings to kernel WireGuard peers.
package registration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
)

const (
	Audience         = "ratatoskr.skaldhall.io/gateway"
	CAAnnotation     = "ratatoskr.skaldhall.io/registration-ca"
	gatewayLabel     = "ratatoskr.skaldhall.io/gateway"
	gatewayNamespace = "ratatoskr.skaldhall.io/gateway-namespace"
	identityLabel    = "ratatoskr.skaldhall.io/gateway-name"
	gatewayUIDLabel  = "ratatoskr.skaldhall.io/gateway-uid"
	defaultTTL       = 5 * time.Minute
)

// PeerManager operates on the gateway's iproute backend. UnregisterPeer must remove
// only the specified pod IP's binding. RegisterPeer atomically replaces its key.
type PeerManager interface {
	RegisterPeer(ctx context.Context, podIP netip.Addr, publicKey string) error
	UnregisterPeer(ctx context.Context, podIP netip.Addr) error
}

// Identity is the gateway's own downward-API Pod identity, never supplied by a client.
type Identity struct{ Namespace, PodName, PodUID, PodIP, GatewayName string }

// IdentityFromEnv reads this gateway Pod's downward-API environment variables.
// POD_NAMESPACE, POD_NAME, POD_UID and POD_IP must be supplied by the deployment;
// the gateway name is trusted local configuration, not registration input.
func IdentityFromEnv(gatewayName string) Identity {
	return Identity{Namespace: os.Getenv("POD_NAMESPACE"), PodName: os.Getenv("POD_NAME"), PodUID: os.Getenv("POD_UID"), PodIP: os.Getenv("POD_IP"), GatewayName: gatewayName}
}

type binding struct {
	namespace, name, uid string
	ip                   netip.Addr
	expires              time.Time
}

// Server uses an uncached API reader for authorization decisions. Caller must
// serve Handler only with TLSConfig, and call ReconcilePeers periodically.
type Server struct {
	Kubernetes kubernetes.Interface
	Reader     client.Reader
	Peers      PeerManager
	Identity   Identity
	TTL        time.Duration
	mu         sync.Mutex
	bindings   map[string]binding
	now        func() time.Time
}

func validIP(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	return ip, err == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback()
}
func (s *Server) ready() bool {
	ip, ok := validIP(s.Identity.PodIP)
	return ok && ip.IsValid() && s.Identity.PodName != "" && s.Identity.PodUID != "" && s.Identity.Namespace != "" && s.Identity.GatewayName != "" && s.Kubernetes != nil && s.Reader != nil && s.Peers != nil
}
func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}
func (s *Server) ttl() time.Duration {
	if s.TTL > 0 && s.TTL <= defaultTTL {
		return s.TTL
	}
	return defaultTTL
}

// Handler is an HTTPS-only handler; it also rejects direct plaintext calls.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.register) }
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != "/v1/peers" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || !s.ready() {
		http.Error(w, "registration unavailable", http.StatusServiceUnavailable)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || token == r.Header.Get("Authorization") || strings.ContainsAny(token, " \t\r\n") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4097))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF || !validKey(req.PublicKey) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	pod, err := s.authenticate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip, _ := validIP(pod.Status.PodIP)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-read before mutation, guarding deletion/recreation between TokenReview and update.
	current, err := s.allowed(r.Context(), pod.Namespace, pod.Name, string(pod.UID))
	if err != nil || current.Spec.ServiceAccountName != pod.Spec.ServiceAccountName || current.Status.PodIP != pod.Status.PodIP {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := pod.Namespace + "/" + pod.Name
	// Never let a new Pod identity claim another live binding's IP: stale
	// ownership is cleared by ReconcilePeers before that IP can be reused.
	for owner, bound := range s.bindings {
		if owner != id && bound.ip == ip {
			http.Error(w, "peer IP already bound", http.StatusConflict)
			return
		}
	}
	if previous, exists := s.bindings[id]; exists && previous.uid != string(pod.UID) {
		http.Error(w, "previous pod binding pending cleanup", http.StatusConflict)
		return
	}
	if previous, exists := s.bindings[id]; exists && previous.ip != ip {
		if err := s.Peers.UnregisterPeer(r.Context(), previous.ip); err != nil {
			http.Error(w, "peer cleanup failed", http.StatusServiceUnavailable)
			return
		}
		delete(s.bindings, id)
	}
	if err = s.Peers.RegisterPeer(r.Context(), ip, req.PublicKey); err != nil {
		http.Error(w, "peer registration failed", http.StatusServiceUnavailable)
		return
	}
	if s.bindings == nil {
		s.bindings = make(map[string]binding)
	}
	s.bindings[id] = binding{pod.Namespace, pod.Name, string(pod.UID), ip, s.clock().Add(s.ttl())}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, "{}")
}
func decodeKey(raw string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(raw) }
func validKey(raw string) bool {
	// WireGuard public keys are canonical 32-byte base64 values. Reject malformed
	// encodings before touching the backend.
	b, err := decodeKey(raw)
	return err == nil && len(b) == 32
}

func (s *Server) authenticate(ctx context.Context, token string) (*corev1.Pod, error) {
	review, err := s.Kubernetes.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{Spec: authv1.TokenReviewSpec{Token: token, Audiences: []string{Audience}}}, metav1.CreateOptions{})
	if err != nil || review == nil || !review.Status.Authenticated || review.Status.Error != "" {
		return nil, errors.New("token review failed")
	}
	hasAudience := false
	for _, a := range review.Status.Audiences {
		if a == Audience {
			hasAudience = true
		}
	}
	if !hasAudience {
		return nil, errors.New("wrong audience")
	}
	username := review.Status.User.Username
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return nil, errors.New("invalid service account")
	}
	parts := strings.Split(strings.TrimPrefix(username, prefix), ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("invalid service account")
	}
	extras := review.Status.User.Extra
	names, uids := extras["authentication.kubernetes.io/pod-name"], extras["authentication.kubernetes.io/pod-uid"]
	if len(names) != 1 || len(uids) != 1 || names[0] == "" || uids[0] == "" {
		return nil, errors.New("missing pod binding")
	}
	pod, err := s.allowed(ctx, parts[0], names[0], uids[0])
	if err != nil || pod.Spec.ServiceAccountName != parts[1] {
		return nil, errors.New("pod authorization failed")
	}
	return pod, nil
}

func (s *Server) allowed(ctx context.Context, namespace, name, uid string) (*corev1.Pod, error) {
	if !s.ready() || namespace == "" || name == "" || uid == "" {
		return nil, errors.New("invalid identity")
	}
	var pod corev1.Pod
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return nil, err
	}
	if string(pod.UID) != uid || pod.DeletionTimestamp != nil || pod.Spec.ServiceAccountName == "" || pod.Labels[gatewayLabel] != s.Identity.GatewayName || pod.Labels[identityLabel] != "" {
		return nil, errors.New("pod not selected")
	}
	ip, ok := validIP(pod.Status.PodIP)
	if !ok || ip.String() != pod.Status.PodIP {
		return nil, errors.New("invalid pod IP")
	}
	target := pod.Labels[gatewayNamespace]
	if target == "" {
		target = pod.Annotations[gatewayNamespace]
	}
	if target == "" {
		target = s.Identity.Namespace
	}
	if target != s.Identity.Namespace {
		return nil, errors.New("wrong gateway namespace")
	}
	var ns corev1.Namespace
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err != nil || ns.DeletionTimestamp != nil {
		return nil, errors.New("namespace unavailable")
	}
	var gw api.EgressGateway
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: s.Identity.Namespace, Name: s.Identity.GatewayName}, &gw); err != nil || gw.DeletionTimestamp != nil || gw.Spec.Encryption != "wireguard" {
		return nil, errors.New("gateway unavailable")
	}
	if gw.Spec.AllowedNamespaces.NamespaceSelector == nil {
		return nil, errors.New("namespace denied")
	}
	selector, err := metav1.LabelSelectorAsSelector(gw.Spec.AllowedNamespaces.NamespaceSelector)
	if err != nil || !selector.Matches(labels.Set(ns.Labels)) {
		return nil, errors.New("namespace denied")
	}
	// Own gateway pod identity is checked against current API state, not caller labels.
	var own corev1.Pod
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: s.Identity.Namespace, Name: s.Identity.PodName}, &own); err != nil || own.DeletionTimestamp != nil || string(own.UID) != s.Identity.PodUID || own.Status.PodIP != s.Identity.PodIP || own.Labels[identityLabel] != gw.Name || own.Labels[gatewayUIDLabel] != string(gw.UID) {
		return nil, errors.New("gateway identity mismatch")
	}
	return &pod, nil
}

// ReconcilePeers expires bindings and rechecks current Pod, Namespace, and
// gateway authorization. Call periodically (e.g. once a minute) and on pod
// deletion events. Errors fail closed: bindings are removed if reads fail.
func (s *Server) ReconcilePeers(ctx context.Context) error {
	if !s.ready() {
		return errors.New("registration unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var failed bool
	for id, b := range s.bindings {
		pod, err := s.allowed(ctx, b.namespace, b.name, b.uid)
		ip, ok := netip.Addr{}, false
		if err == nil {
			ip, ok = validIP(pod.Status.PodIP)
		}
		if err == nil && ok && ip == b.ip && s.clock().Before(b.expires) {
			continue
		}
		if err := s.Peers.UnregisterPeer(ctx, b.ip); err != nil {
			failed = true
			continue
		}
		delete(s.bindings, id)
	}
	if failed {
		return errors.New("peer cleanup failed")
	}
	return nil
}

// RemoveDeletedPod removes only the recorded UID; stale informer events cannot
// remove a replacement Pod's binding.
func (s *Server) RemoveDeletedPod(ctx context.Context, namespace, name, uid string) error {
	if s.Peers == nil || uid == "" {
		return errors.New("registration unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := namespace + "/" + name
	b, ok := s.bindings[id]
	if !ok || b.uid != uid {
		return nil
	}
	if err := s.Peers.UnregisterPeer(ctx, b.ip); err != nil {
		return errors.New("peer cleanup failed")
	}
	delete(s.bindings, id)
	return nil
}

// PublishCA annotates only this exact gateway Pod with public certificate PEM.
func (s *Server) PublishCA(ctx context.Context, caPEM []byte) error {
	if !s.ready() || !publicCA(caPEM) {
		return errors.New("registration unavailable")
	}
	pod, err := s.Kubernetes.CoreV1().Pods(s.Identity.Namespace).Get(ctx, s.Identity.PodName, metav1.GetOptions{})
	if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) != s.Identity.PodUID || pod.Status.PodIP != s.Identity.PodIP || pod.Labels[identityLabel] != s.Identity.GatewayName {
		return errors.New("gateway pod unavailable")
	}
	var gateway api.EgressGateway
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: s.Identity.Namespace, Name: s.Identity.GatewayName}, &gateway); err != nil || gateway.DeletionTimestamp != nil || gateway.Spec.Encryption != "wireguard" || pod.Labels[gatewayUIDLabel] != string(gateway.UID) {
		return errors.New("gateway identity mismatch")
	}
	copy := pod.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[CAAnnotation] = string(caPEM)
	_, err = s.Kubernetes.CoreV1().Pods(s.Identity.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return errors.New("CA publication failed")
	}
	return nil
}
func publicCA(data []byte) bool {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
		return false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	return err == nil && c.IsCA
}

// Certificates contains only the public CA and an unexported in-memory TLS key.
type Certificates struct {
	caPEM  []byte
	config *tls.Config
}

func (c *Certificates) PublicCert() []byte { return append([]byte(nil), c.caPEM...) }
func (c *Certificates) TLSConfig(gatewayPodIP string) (*tls.Config, error) {
	ip, ok := validIP(gatewayPodIP)
	if !ok || c == nil || c.config == nil || c.config.Certificates[0].Leaf == nil || len(c.config.Certificates[0].Leaf.IPAddresses) != 1 || c.config.Certificates[0].Leaf.IPAddresses[0].String() != ip.String() {
		return nil, errors.New("invalid gateway TLS identity")
	}
	return c.config.Clone(), nil
}

// NewCertificates generates a new ephemeral CA and serving key per process.
// Neither private key is serialized, logged or returned.
func NewCertificates(gatewayPodIP string) (*Certificates, error) {
	ip, ok := validIP(gatewayPodIP)
	if !ok {
		return nil, errors.New("invalid gateway IP")
	}
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ratatoskr gateway ephemeral CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ratatoskr gateway"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), IPAddresses: []net.IP{net.IP(ip.AsSlice())}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: parsed}
	return &Certificates{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), config: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}}, nil
}
