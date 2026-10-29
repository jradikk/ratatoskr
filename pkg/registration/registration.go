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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
)

const (
	Audience                     = "ratatoskr.skaldhall.io/gateway"
	CAAnnotation                 = "ratatoskr.skaldhall.io/registration-ca"
	WireGuardPublicKeyAnnotation = "ratatoskr.skaldhall.io/wireguard-public-key"
	gatewayLabel                 = "ratatoskr.skaldhall.io/gateway"
	gatewayNamespace             = "ratatoskr.skaldhall.io/gateway-namespace"
	identityLabel                = "ratatoskr.skaldhall.io/gateway-name"
	gatewayUIDLabel              = "ratatoskr.skaldhall.io/gateway-uid"
	defaultTTL                   = 24 * time.Hour
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

// errTransient marks API availability failures, never confirmed authorization
// failures. A failed read has at most one TTL of grace after last validation.
var errTransient = errors.New("authorization API unavailable")

func readError(err error) error {
	if apierrors.IsNotFound(err) {
		return errors.New("authorization object missing")
	}
	return errTransient
}

func (s *Server) allowed(ctx context.Context, namespace, name, uid string) (*corev1.Pod, error) {
	if !s.ready() || namespace == "" || name == "" || uid == "" {
		return nil, errors.New("invalid identity")
	}
	var pod corev1.Pod
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return nil, readError(err)
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
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err != nil {
		return nil, readError(err)
	}
	if ns.DeletionTimestamp != nil {
		return nil, errors.New("namespace terminating")
	}
	var gw api.EgressGateway
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: s.Identity.Namespace, Name: s.Identity.GatewayName}, &gw); err != nil {
		return nil, readError(err)
	}
	if gw.DeletionTimestamp != nil || gw.Spec.Encryption != "wireguard" {
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
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: s.Identity.Namespace, Name: s.Identity.PodName}, &own); err != nil {
		return nil, readError(err)
	}
	if own.DeletionTimestamp != nil || string(own.UID) != s.Identity.PodUID || own.Status.PodIP != s.Identity.PodIP || own.Labels[identityLabel] != gw.Name || own.Labels[gatewayUIDLabel] != string(gw.UID) {
		return nil, errors.New("gateway identity mismatch")
	}
	return &pod, nil
}

// ReconcilePeers expires bindings and rechecks current Pod, Namespace, and
// gateway authorization. Call periodically (e.g. once a minute) and on pod
// deletion events. A confirmed allowed Pod refreshes its TTL, including after
// a long gap. Temporary API failures retain peers only until the last verified
// authorization expires (at most 24h); known deletion/opt-out fails closed.
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
		if err == nil && ok && ip == b.ip {
			b.expires = s.clock().Add(s.ttl())
			s.bindings[id] = b
			continue
		}
		if errors.Is(err, errTransient) && s.clock().Before(b.expires) {
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

// PublishCA is retained for callers that publish only the public CA. WireGuard
// gateways must use PublishPublicIdentity to publish both values atomically.
func (s *Server) PublishCA(ctx context.Context, caPEM []byte) error {
	return s.publish(ctx, caPEM, "", false)
}

// PublishPublicIdentity atomically publishes the CA and a syntactically valid
// WireGuard public key to this verified gateway Pod. Callers must pass the
// backend's WireGuardPublicKey; 32-byte public and private keys cannot be
// distinguished from their base64 representation alone.
func (s *Server) PublishPublicIdentity(ctx context.Context, caPEM []byte, wgPublicKey string) error {
	key, err := decodeKey(wgPublicKey)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != wgPublicKey {
		return errors.New("invalid WireGuard public key")
	}
	return s.publish(ctx, caPEM, wgPublicKey, true)
}

func (s *Server) publish(ctx context.Context, caPEM []byte, wgPublicKey string, includeKey bool) error {
	if !s.ready() || !publicCA(caPEM) {
		return errors.New("registration unavailable")
	}
	pods := s.Kubernetes.CoreV1().Pods(s.Identity.Namespace)
	for attempt := 0; attempt < 3; attempt++ {
		pod, err := pods.Get(ctx, s.Identity.PodName, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) != s.Identity.PodUID || pod.Status.PodIP != s.Identity.PodIP || pod.Labels[identityLabel] != s.Identity.GatewayName {
			return errors.New("gateway pod unavailable")
		}
		var gateway api.EgressGateway
		if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: s.Identity.Namespace, Name: s.Identity.GatewayName}, &gateway); err != nil || gateway.DeletionTimestamp != nil || gateway.Spec.Encryption != "wireguard" || pod.Labels[gatewayUIDLabel] != string(gateway.UID) {
			return errors.New("gateway identity mismatch")
		}
		// JSON Patch preconditions prevent updating a replacement Pod or applying
		// the CA against stale metadata; only our own annotation is modified.
		operations := []map[string]any{
			{"op": "test", "path": "/metadata/uid", "value": string(pod.UID)},
			{"op": "test", "path": "/metadata/resourceVersion", "value": pod.ResourceVersion},
		}
		if pod.Annotations == nil {
			annotationValues := map[string]string{CAAnnotation: string(caPEM)}
			if includeKey {
				annotationValues[WireGuardPublicKeyAnnotation] = wgPublicKey
			}
			operations = append(operations, map[string]any{"op": "add", "path": "/metadata/annotations", "value": annotationValues})
		} else {
			operations = append(operations, map[string]any{"op": "add", "path": "/metadata/annotations/ratatoskr.skaldhall.io~1registration-ca", "value": string(caPEM)})
			if includeKey {
				operations = append(operations, map[string]any{"op": "add", "path": "/metadata/annotations/ratatoskr.skaldhall.io~1wireguard-public-key", "value": wgPublicKey})
			}
		}
		patch, err := json.Marshal(operations)
		if err != nil {
			return errors.New("CA publication failed")
		}
		if _, err = pods.Patch(ctx, s.Identity.PodName, types.JSONPatchType, patch, metav1.PatchOptions{}); err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) && !apierrors.IsInvalid(err) && !apierrors.IsBadRequest(err) {
			return errors.New("CA publication failed")
		}
		// Conflict/precondition rejection may be a Pod replacement: GET and
		// revalidate identity before retrying, never blindly retrying the patch.
	}
	return errors.New("CA publication failed")
}
func publicCA(data []byte) bool {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
		return false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	return err == nil && c.IsCA
}

// Certificates owns a process-local CA signing key and rotates short-lived
// serving leaves in memory. The published CA never changes in this process.
type Certificates struct {
	mu    sync.Mutex
	caPEM []byte
	ca    *x509.Certificate
	caKey ed25519.PrivateKey
	ip    netip.Addr
	leaf  *tls.Certificate
	now   func() time.Time
}

const (
	caRenewalDeadline = 30 * 24 * time.Hour
	leafLifetime      = 30 * 24 * time.Hour
	leafRenewalWindow = 7 * 24 * time.Hour
)

func (c *Certificates) PublicCert() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.caPEM...)
}

// TLSConfig installs a dynamic GetCertificate callback; callers must use this
// config rather than copying an initial serving certificate into their server.
// No external scheduler is required: each handshake checks for leaf renewal.
func (c *Certificates) TLSConfig(gatewayPodIP string) (*tls.Config, error) {
	ip, ok := validIP(gatewayPodIP)
	if !ok || c == nil || c.ip != ip || c.leaf == nil {
		return nil, errors.New("invalid gateway TLS identity")
	}
	if _, err := c.currentCertificate(nil); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: c.currentCertificate}, nil
}

// currentCertificate serializes renewal, then returns an immutable leaf
// pointer safe for concurrent handshakes. Never return the signing key in an
// error (or write it to a Kubernetes resource).
func (c *Certificates) currentCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now == nil || c.ca == nil || c.leaf == nil {
		return nil, errors.New("gateway TLS identity unavailable")
	}
	now := c.now()
	if now.Before(c.ca.NotBefore) || !now.Add(caRenewalDeadline).Before(c.ca.NotAfter) {
		return nil, errors.New("gateway CA nearing expiry; restart gateway to publish a new CA")
	}
	if !now.Add(leafRenewalWindow).Before(c.leaf.Leaf.NotAfter) || now.Before(c.leaf.Leaf.NotBefore) {
		leaf, err := c.issueLeaf(now)
		if err != nil {
			return nil, errors.New("gateway serving certificate renewal failed")
		}
		c.leaf = leaf
	}
	return c.leaf, nil
}

func (c *Certificates) issueLeaf(now time.Time) (*tls.Certificate, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ratatoskr gateway"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(leafLifetime), IPAddresses: []net.IP{net.IP(c.ip.AsSlice())}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, c.ca, pub, c.caKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER, c.ca.Raw}, PrivateKey: key, Leaf: parsed}, nil
}

// NewCertificates creates an in-memory CA valid for five years; serving leaves
// rotate under the same CA before their 30-day validity expires. A gateway must
// be replaced and its new CA published before the CA's final 30 days.
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
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	caTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ratatoskr gateway ephemeral CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	c := &Certificates{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), ca: ca, caKey: caKey, ip: ip, now: time.Now}
	c.leaf, err = c.issueLeaf(now)
	if err != nil {
		return nil, errors.New("certificate generation failed")
	}
	return c, nil
}
