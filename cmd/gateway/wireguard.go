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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
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
		if e := srv.Serve(tls.NewListener(listener, tlsConfig)); e != nil && !errors.Is(e, http.ErrServerClosed) {
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
