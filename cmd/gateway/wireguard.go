package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/registration"
)

type authorizedGatewayPeers struct {
	backend   *iproute.Backend
	gatewayIP netip.Addr
}

func (p authorizedGatewayPeers) RegisterPeer(ctx context.Context, ip netip.Addr, key string) error {
	return p.backend.RegisterPeer(ctx, p.gatewayIP, ip, key)
}
func (p authorizedGatewayPeers) UnregisterPeer(ctx context.Context, ip netip.Addr) error {
	return p.backend.UnregisterPeer(ctx, ip)
}

// markedRegistrationListener forces server-side HTTPS replies over eth0 even
// after authenticated peer registration creates a /32 WG route to the client.
// Without SO_MARK on accepted sockets, the success response could instead be
// sent through WG before client init has installed its peer, deadlocking setup.
type markedRegistrationListener struct {
	net.Listener
	mark uint32
}

func (l markedRegistrationListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("registration listener accepted non-TCP socket")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		_ = c.Close()
		return nil, errors.New("registration socket unavailable")
	}
	var sockErr error
	if err = raw.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(l.mark)) }); err != nil {
		_ = c.Close()
		return nil, errors.New("mark registration socket failed")
	}
	if sockErr != nil {
		_ = c.Close()
		return nil, errors.New("mark registration socket failed")
	}
	return c, nil
}

// startEncryptedGateway publishes only public keys/certificates after creating
// the kernel identity. TLS private keys, WireGuard private keys and bearer tokens
// never enter Kubernetes resources, logs or the upstream container mount.
func startEncryptedGateway(ctx context.Context, gatewayName string, podIP netip.Addr, backend *iproute.Backend, errorsCh chan<- error) (func(), error) {
	identity := registration.IdentityFromEnv(gatewayName)
	if identity.PodIP != podIP.String() || identity.PodName == "" || identity.PodUID == "" || identity.Namespace == "" || identity.GatewayName == "" {
		return nil, errors.New("gateway downward identity incomplete")
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("load gateway Kubernetes client: %w", err)
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err = api.AddToScheme(scheme); err != nil {
		return nil, err
	}
	reader, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	cert, err := registration.NewCertificates(podIP.String())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := cert.TLSConfig(podIP.String())
	if err != nil {
		return nil, err
	}
	key, err := backend.WireGuardPublicKey()
	if err != nil {
		return nil, errors.New("gateway WireGuard public key unavailable")
	}
	// A container process may restart within the same Pod/netns: the kernel WG
	// device and peers survive, but our in-memory TokenReview bindings do not.
	// Revoke old peers before publishing this process's new TLS identity/Ready.
	if err := backend.ClearGatewayPeers(ctx); err != nil {
		return nil, fmt.Errorf("revoke unauthenticated persisted gateway peers: %w", err)
	}
	peers := &registration.Server{Kubernetes: kube, Reader: reader, Peers: authorizedGatewayPeers{backend: backend, gatewayIP: podIP}, Identity: identity}
	if err = peers.PublishPublicIdentity(ctx, cert.PublicCert(), key); err != nil {
		return nil, fmt.Errorf("publish gateway public registration identity: %w", err)
	}
	listener, err := net.Listen("tcp4", ":9443") // #nosec G102 -- registration API must bind the gateway Pod IP; NetworkPolicy restricts ingress and TokenReview authenticates every request.
	if err != nil {
		return nil, fmt.Errorf("listen authenticated peer registration: %w", err)
	}
	srv := &http.Server{Handler: peers.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	watchCtx, stopWatch := context.WithCancel(ctx)
	go func() {
		if e := srv.Serve(tls.NewListener(markedRegistrationListener{Listener: listener, mark: datapath.WireGuardMark}, tlsConfig)); e != nil && !errors.Is(e, http.ErrServerClosed) {
			select {
			case errorsCh <- fmt.Errorf("peer registration listener: %w", e):
			default:
			}
		}
	}()
	go func() {
		if e := peers.WatchPods(watchCtx); e != nil && watchCtx.Err() == nil {
			select {
			case errorsCh <- fmt.Errorf("peer watch unavailable: %w", e):
			default:
			}
		}
	}()
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-tick.C:
				if e := peers.ReconcilePeers(watchCtx); e != nil && watchCtx.Err() == nil {
					select {
					case errorsCh <- fmt.Errorf("peer reconciliation unavailable: %w", e):
					default:
					}
				}
			}
		}
	}()
	return func() {
		stopWatch()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}, nil
}
