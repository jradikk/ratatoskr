//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/fqdn"
	"github.com/skaldhall/ratatoskr/pkg/policy"
)

// domainOperations keeps kernel-only effects injectable for offline race/failure
// tests. Production defaults always use verified netns entry and marked sockets.
type domainOperations struct {
	marker         func() error
	clearMarker    func() error
	measure        func(*datapath.ClientConfig) error
	mark           func(int) error
	own            func(context.Context) error
	enter          func(*os.File, func() error) error
	verifyTarget   func(netip.Addr) error
	recheck        func(context.Context, cri.RuntimeServiceClient, sandboxProof, *os.File) error
	sandbox        func(context.Context, cri.RuntimeServiceClient, string, string, string, string) (*os.File, sandboxProof, error)
	program        func(context.Context, *os.File, *datapath.ClientConfig, int, string, bool, BackendFactory, string) error
	quarantine     func(*os.File, netip.Addr) error
	redirect       func(netip.Addr) error
	verifyRedirect func(netip.Addr) error
	removeRedirect func(netip.Addr) error
	listenPacket   func(string, string) (net.PacketConn, error)
	listen         func(string, string) (net.Listener, error)
	dial           func(context.Context, string, string, func(string, string, syscall.RawConn) error) (net.Conn, error)
	interval       time.Duration
}

// Domain programming deliberately withholds the marker. The DNS capture and
// optimistic persisted state must be established before wait-init can proceed.
func programDomain(ctx context.Context, target *os.File, cfg *datapath.ClientConfig, gatewayMTU int, _ string, _ bool, factory BackendFactory, _ string) error {
	return InNamespace(target, func() error {
		if err := verifyTargetPodIPv4(cfg.PodIP); err != nil {
			return err
		}
		if err := guardWorkload(); err != nil {
			return err
		}
		if err := clearReadyMarker(); err != nil {
			return err
		}
		backend, err := factory()
		if err != nil {
			return err
		}
		defer backend.Close()
		measured := *cfg
		measured.MTU = gatewayMTU
		if err = completeClientMTU(&measured); err != nil {
			return err
		}
		if measured.MTU != cfg.MTU {
			return errors.New("domain client MTU changed during application")
		}
		return backend.ApplyClient(ctx, *cfg)
	})
}

func (r *Reconciler) domainOperations() domainOperations {
	if r.domainOps != nil {
		return *r.domainOps
	}
	return domainOperations{marker: func() error {
		link, err := netlink.LinkByName(Marker)
		if err == nil {
			return netlink.LinkSetUp(link)
		}
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return err
		}
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: Marker}}
		if err = netlink.LinkAdd(dummy); err != nil {
			return err
		}
		return netlink.LinkSetUp(dummy)
	}, clearMarker: clearReadyMarker, measure: completeClientMTU, mark: func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(iproute.DNSControlMark))
	}, own: r.VerifyOwnPod, enter: InNamespace, verifyTarget: verifyTargetPodIPv4, recheck: recheckSandbox, sandbox: Sandbox, program: programDomain, quarantine: quarantineUnknownAuthorization, redirect: iproute.InstallDNSRedirect, verifyRedirect: iproute.VerifyDNSRedirect, removeRedirect: iproute.RemoveDNSRedirect, listenPacket: net.ListenPacket, listen: net.Listen, dial: func(ctx context.Context, network, address string, control func(string, string, syscall.RawConn) error) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second, Control: control}).DialContext(ctx, network, address)
	}, interval: time.Second}
}

type domainRuntime struct {
	gatewayUID                      string
	uid, namespace, name, policyUID string
	generation                      int64
	resolver                        netip.Addr
	gateway                         types.NamespacedName
	proxy                           *fqdn.Proxy
	udp                             net.PacketConn
	tcp                             net.Listener
	servers                         []*mdns.Server
	podIP                           netip.Addr
	netns                           *os.File
	inode                           unix.Stat_t
	retired                         atomic.Bool
	poisoned                        bool // protected by the per-UID lock
	stop                            chan struct{}
	done                            chan struct{}
	closeOnce                       sync.Once
}

func (rt *domainRuntime) close() {
	rt.closeOnce.Do(func() {
		rt.retired.Store(true)
		if rt.stop != nil {
			close(rt.stop)
		}
		if rt.udp != nil {
			_ = rt.udp.Close()
		}
		if rt.tcp != nil {
			_ = rt.tcp.Close()
		}
		// NEVER wait for DNS callbacks while holding the perUID lock they acquire.
		go func() {
			for _, server := range rt.servers {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = server.ShutdownContext(ctx)
				cancel()
			}
			if rt.netns != nil {
				_ = rt.netns.Close()
			}
			if rt.done != nil {
				close(rt.done)
			}
		}()
	})
}
func (r *Reconciler) domainLock(uid string) *sync.Mutex {
	r.domainMu.Lock()
	defer r.domainMu.Unlock()
	if r.domainLocks == nil {
		r.domainLocks = map[string]*sync.Mutex{}
	}
	if r.domainLocks[uid] == nil {
		r.domainLocks[uid] = &sync.Mutex{}
	}
	return r.domainLocks[uid]
}
func (r *Reconciler) domainRuntime(uid string) *domainRuntime {
	r.domainMu.Lock()
	defer r.domainMu.Unlock()
	return r.domains[uid]
}
func (r *Reconciler) putDomain(uid string, rt *domainRuntime) {
	r.domainMu.Lock()
	defer r.domainMu.Unlock()
	if r.domains == nil {
		r.domains = map[string]*domainRuntime{}
	}
	r.domains[uid] = rt
}
func (r *Reconciler) retireDomain(uid string) {
	r.domainMu.Lock()
	old := r.domains[uid]
	delete(r.domains, uid)
	r.domainMu.Unlock()
	if old != nil {
		old.close()
	}
}
func (r *Reconciler) closeDomains() {
	r.domainMu.Lock()
	runtimes := r.domains
	r.domains = nil
	r.domainMu.Unlock()
	for _, rt := range runtimes {
		lock := r.domainLock(rt.uid)
		lock.Lock()
		rt.close()
		lock.Unlock()
	}
	for _, rt := range runtimes {
		if rt.done != nil {
			select {
			case <-rt.done:
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// Fresh API state, not a queued event snapshot, decides annotation/config restore.
func (r *Reconciler) refreshDomainPod(ctx context.Context, pod *corev1.Pod) error {
	if r.domainRuntime(string(pod.UID)) == nil && !strings.Contains(pod.Annotations[ConfigAnnotation], "domainPolicyUID") {
		return nil
	}
	var current corev1.Pod
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, &current); err != nil {
		return err
	}
	if current.UID != pod.UID {
		return errors.New("domain workload identity replaced")
	}
	*pod = *current.DeepCopy()
	return nil
}

func restoreDomainConfig(pod *corev1.Pod, cfg *datapath.ClientConfig, pol api.EgressPolicy, mode string) error {
	rules, err := policy.DomainRules(pol.Spec)
	if err != nil {
		return err
	}
	if existing := pod.Annotations[HashAnnotation]; existing != "" {
		var old datapath.ClientConfig
		if json.Unmarshal([]byte(pod.Annotations[ConfigAnnotation]), &old) != nil ||
			HashForMode(old, mode) != existing || old.Identity.UID != string(pod.UID) ||
			old.Identity.Namespace != pod.Namespace || old.Identity.Pod != pod.Name || old.PodIP != cfg.PodIP {
			return errors.New("unauthenticated retained DNS state")
		}
		if old.DomainPolicyUID == cfg.DomainPolicyUID && old.DomainPolicyGeneration == cfg.DomainPolicyGeneration {
			cfg.DomainState = append([]datapath.DomainBinding(nil), old.DomainState...)
		}
	}
	proxy, err := fqdn.New(fqdn.Options{Mode: cfg.Policy.Mode, Rules: rules, Resolver: "127.0.0.1:53", Restore: cfg.DomainState,
		Apply: func(context.Context, fqdn.Update) error { return nil }})
	if err != nil {
		return err
	}
	if err = proxy.Sync(context.Background()); err != nil {
		return err
	}
	snapshot := proxy.Snapshot()
	cfg.Policy.Rules = snapshot.Rules
	cfg.DomainState = append([]datapath.DomainBinding(nil), snapshot.State...)
	return cfg.Validate()
}
func (r *Reconciler) domainResolver(ctx context.Context, gw *api.EgressGateway) (netip.Addr, error) {
	if gw.Spec.DNS.Mode != "gateway" {
		return netip.Addr{}, errors.New("domain routing requires gateway DNS")
	}
	var svc corev1.Service
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name + "-dns"}, &svc); err != nil {
		return netip.Addr{}, err
	}
	if svc.DeletionTimestamp != nil || !metav1.IsControlledBy(&svc, gw) {
		return netip.Addr{}, errors.New("gateway DNS service owner differs")
	}
	ip, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || svc.Spec.Type != corev1.ServiceTypeClusterIP {
		return netip.Addr{}, errors.New("gateway DNS Service IPv4 invalid")
	}
	if len(svc.Spec.Ports) != 2 {
		return netip.Addr{}, errors.New("gateway DNS Service ports changed")
	}
	ports := map[corev1.Protocol]bool{}
	for _, p := range svc.Spec.Ports {
		if p.Port != 53 || p.TargetPort.IntVal != 1053 || ports[p.Protocol] {
			return netip.Addr{}, errors.New("gateway DNS Service port invalid")
		}
		ports[p.Protocol] = true
	}
	if !ports[corev1.ProtocolUDP] || !ports[corev1.ProtocolTCP] {
		return netip.Addr{}, errors.New("gateway DNS Service protocol missing")
	}
	return ip, nil
}

type domainStartupError struct{ stage, category string }

func (e *domainStartupError) Error() string {
	return "DNS startup blocked: " + e.stage + " (" + e.category + ")"
}
func domainStartupFailure(stage string, cause error) error {
	category := "invalid-or-unavailable"
	switch {
	case apierrors.IsForbidden(cause) || apierrors.IsUnauthorized(cause):
		category = "permission-denied"
	case apierrors.IsNotFound(cause):
		category = "service-not-found"
	case errors.Is(cause, unix.EADDRINUSE):
		category = "address-in-use"
	case errors.Is(cause, unix.EPERM) || errors.Is(cause, unix.EACCES):
		category = "permission-denied"
	case errors.Is(cause, unix.EADDRNOTAVAIL) || errors.Is(cause, unix.ENODEV):
		category = "address-unavailable"
	case errors.Is(cause, context.DeadlineExceeded):
		category = "timeout"
	case errors.Is(cause, context.Canceled):
		category = "cancelled"
	}
	return &domainStartupError{stage: stage, category: category}
}
func (r *Reconciler) startDomain(ctx context.Context, pod *corev1.Pod, gw *api.EgressGateway, pol *api.EgressPolicy, cfg datapath.ClientConfig, target *os.File, proof sandboxProof, mode string) (err error) {
	stage := "policy-identity"
	defer func() {
		if err != nil {
			err = domainStartupFailure(stage, err)
		}
	}()
	if cfg.DomainPolicyUID == "" || cfg.DomainPolicyGeneration <= 0 || gw.UID == "" {
		return errors.New("domain runtime requires persisted authorization identities")
	}
	stage = "resolver-service"
	ip, err := r.domainResolver(ctx, gw)
	if err != nil {
		return err
	}

	stage = "pod-dns-config"
	if pod.Spec.DNSPolicy != corev1.DNSNone || pod.Spec.DNSConfig == nil || len(pod.Spec.DNSConfig.Nameservers) != 1 || pod.Spec.DNSConfig.Nameservers[0] != ip.String() {
		return errors.New("domain workload must use gateway DNS only")
	}
	stage = "runtime-identity"
	uid := string(pod.UID)
	if old := r.domainRuntime(uid); old != nil && (old.policyUID != string(pol.UID) || old.generation != pol.Generation || old.resolver != ip) {
		// An old redirect still owns the former gateway DNS Service. Do not
		// silently leave two selectors installed for a changed policy.
		return r.poisonDomain(old, target, pod, errors.New("domain policy/Service changed; recreate selected Pod"))
	}
	if old := r.domainRuntime(uid); old != nil && old.poisoned {
		return errors.New("DNS workload fenced; recreate Pod")
	}
	if old := r.domainRuntime(uid); old != nil && !old.retired.Load() {
		var inode unix.Stat_t
		if err = unix.Fstat(int(target.Fd()), &inode); err != nil || !sameNetns(inode, old.inode) || old.gatewayUID != string(gw.UID) {
			return r.poisonDomain(old, target, pod, errors.New("domain sandbox or gateway replaced"))
		}
		if err = r.domainOperations().enter(target, func() error { return r.domainOperations().verifyRedirect(ip) }); err == nil {
			stage = "state-persist"
			if err = r.patchDomainReady(ctx, pod, cfg, mode); err != nil {
				return r.poisonDomain(old, target, pod, err)
			}
			stage = "ready-marker"
			if err = r.domainOperations().enter(target, r.domainOperations().marker); err != nil {
				return r.poisonDomain(old, target, pod, err)
			}
			return nil
		}
		return r.poisonDomain(old, target, pod, errors.New("DNS interception missing"))
	}
	r.retireDomain(uid)
	rt := &domainRuntime{stop: make(chan struct{}), done: make(chan struct{}), uid: uid, namespace: pod.Namespace, name: pod.Name, policyUID: string(pol.UID), generation: pol.Generation, resolver: ip, podIP: cfg.PodIP, gatewayUID: string(gw.UID), gateway: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}}
	stage = "namespace-duplicate"
	fd, e := unix.Dup(int(target.Fd()))
	if e != nil {
		return e
	}
	rt.netns = os.NewFile(uintptr(fd), "selected-dns-netns")
	if err = unix.Fstat(fd, &rt.inode); err != nil {
		rt.close()
		return err
	}
	stage = "policy-cache"
	rules, err := policy.DomainRules(pol.Spec)
	if err != nil {
		rt.close()
		return err
	}
	rt.proxy, err = fqdn.New(fqdn.Options{Mode: cfg.Policy.Mode, Rules: rules, Resolver: net.JoinHostPort(ip.String(), "53"), Restore: cfg.DomainState,
		Apply: func(c context.Context, u fqdn.Update) error { return r.applyDomain(c, rt, u) },
		Exchange: func(c context.Context, m *mdns.Msg, resolver, proto string) (*mdns.Msg, error) {
			return r.exchangeDomain(c, rt, m, resolver, proto)
		},
	})
	if err != nil {
		rt.close()
		return err
	}
	stage = "namespace-recheck"
	if err = r.domainOperations().recheck(ctx, r.CRI, proof, target); err != nil {
		rt.close()
		return err
	}
	// Sockets are created on the locked target thread, not inside the app Pod.
	err = r.domainOperations().enter(target, func() error {
		stage = "udp-listener"
		rt.udp, err = r.domainOperations().listenPacket("udp4", "127.0.0.1:1053")
		if err != nil {
			return err
		}
		stage = "tcp-listener"
		rt.tcp, err = r.domainOperations().listen("tcp4", "127.0.0.1:1053")
		return err
	})
	if err != nil {
		rt.close()
		return err
	}
	stage = "listener-start"
	r.putDomain(uid, rt)
	// The server loop is running before redirect; callbacks serialize on the UID
	// lock and cannot release answers until the initial authoritative patch.
	for _, server := range []*mdns.Server{{PacketConn: rt.udp, Net: "udp", Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		if rt.retired.Load() {
			m := new(mdns.Msg).SetRcode(q, mdns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		rt.proxy.ServeDNS(w, q)
	})}, {Listener: rt.tcp, Net: "tcp", Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		if rt.retired.Load() {
			m := new(mdns.Msg).SetRcode(q, mdns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		rt.proxy.ServeDNS(w, q)
	})}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		rt.servers = append(rt.servers, server)
		go func(srv *mdns.Server) {
			if err := srv.ActivateAndServe(); err != nil && !rt.retired.Load() {
				lock := r.domainLock(rt.uid)
				lock.Lock()
				if !rt.retired.Load() {
					_ = r.poisonDomain(rt, rt.netns, pod, errors.New("owned DNS server stopped"))
				}
				lock.Unlock()
			}
		}(server)
		select {
		case <-ready:
		case <-ctx.Done():
			return r.poisonDomain(rt, target, pod, ctx.Err())
		case <-time.After(3 * time.Second):
			return r.poisonDomain(rt, target, pod, errors.New("owned DNS listener startup timeout"))
		}
	}
	stage = "dns-redirect"
	if err = r.domainOperations().enter(target, func() error { return r.domainOperations().redirect(ip) }); err != nil {
		return r.poisonDomainReason(rt, target, pod, quarantineDomainRedirect)
	}
	stage = "state-persist"
	if err = r.patchDomainReady(ctx, pod, cfg, mode); err != nil {
		return r.poisonDomainReason(rt, target, pod, quarantineDomainPersistence)
	}
	stage = "ready-marker"
	if err = r.domainOperations().enter(target, r.domainOperations().marker); err != nil {
		return r.poisonDomainReason(rt, target, pod, quarantineDomainRuntime)
	}
	go r.syncDomain(ctx, rt) // #nosec G118 -- process-lived worker inherits ctx; bounded fresh contexts are only for fail-closed compensation.
	return nil
}
func (r *Reconciler) patchDomainReady(ctx context.Context, pod *corev1.Pod, cfg datapath.ClientConfig, mode string) error {
	original := pod.DeepCopy()
	pod.Annotations = copyAnnotations(pod.Annotations)
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	pod.Annotations[HashAnnotation] = HashForMode(cfg, mode)
	pod.Annotations[BackendAnnotation] = mode
	pod.Annotations[ConfigAnnotation] = string(raw)
	pod.Annotations[ReadyAnnotation] = "true"
	if err = r.Client.Patch(ctx, pod, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
		return err
	}
	return nil
}
func (r *Reconciler) applyDomain(ctx context.Context, rt *domainRuntime, u fqdn.Update) (err error) {
	lock := r.domainLock(rt.uid)
	lock.Lock()
	defer lock.Unlock()
	defer func() {
		if err != nil && !rt.retired.Load() {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: rt.name, Namespace: rt.namespace, UID: types.UID(rt.uid)}, Status: corev1.PodStatus{PodIP: rt.podIP.String()}}
			err = r.poisonDomainReason(rt, rt.netns, pod, quarantineDomainRouting)
		}
	}()
	if rt.retired.Load() || rt.poisoned {
		return errors.New("DNS runtime retired")
	}
	if err = r.domainOperations().own(ctx); err != nil {
		return err
	}
	var pod corev1.Pod
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: rt.namespace, Name: rt.name}, &pod); err != nil {
		return err
	}
	if string(pod.UID) != rt.uid || pod.DeletionTimestamp != nil || pod.Spec.NodeName != r.Node || pod.Spec.HostNetwork || pod.Status.PodIP != rt.podIP.String() || pod.Annotations[ReadyAnnotation] != "true" {
		return errors.New("selected DNS Pod identity changed")
	}
	var gw api.EgressGateway
	if err := r.Client.Get(ctx, rt.gateway, &gw); err != nil {
		return err
	}
	if gw.DeletionTimestamp != nil || gw.Spec.DNS.Mode != "gateway" || string(gw.UID) != rt.gatewayUID {
		return errors.New("gateway DNS authorization changed")
	}
	resolver, e := r.domainResolver(ctx, &gw)
	if e != nil || resolver != rt.resolver {
		return errors.New("domain resolver authorization changed")
	}
	if pod.Spec.DNSPolicy != corev1.DNSNone || pod.Spec.DNSConfig == nil || len(pod.Spec.DNSConfig.Nameservers) != 1 || pod.Spec.DNSConfig.Nameservers[0] != resolver.String() {
		return errors.New("domain workload resolver changed")
	}
	var ns corev1.Namespace
	if err := r.Client.Get(ctx, types.NamespacedName{Name: pod.Namespace}, &ns); err != nil {
		return err
	}
	var policies api.EgressPolicyList
	if err := r.Client.List(ctx, &policies, client.InNamespace(pod.Namespace)); err != nil {
		return err
	}
	var pol *api.EgressPolicy
	for i := range policies.Items {
		if string(policies.Items[i].UID) == rt.policyUID && policies.Items[i].Generation == rt.generation {
			pol = &policies.Items[i]
			break
		}
	}
	if pol == nil {
		return errors.New("DNS policy identity changed")
	}
	cfg, err := Config(&pod, &ns, &gw, policies.Items, r.OperatorNamespace)
	if err != nil {
		return err
	}
	if gw.UID == "" || cfg.DomainPolicyUID != rt.policyUID || cfg.DomainPolicyGeneration != rt.generation {
		return errors.New("DNS policy mismatch")
	}
	if err = restoreDomainConfig(&pod, &cfg, *pol, backendMode(r.Datapath)); err != nil {
		return err
	}
	next := cfg
	next.Policy.Rules = append([]datapath.Rule(nil), u.Rules...)
	next.DomainState = append([]datapath.DomainBinding(nil), u.State...)
	if err = next.Validate(); err != nil {
		return err
	}
	target, proof, err := r.domainOperations().sandbox(ctx, r.CRI, pod.Namespace, pod.Name, string(pod.UID), pod.Status.PodIP)
	if err != nil {
		return err
	}
	defer target.Close()
	defer func() {
		if proof.pidfd >= 0 {
			_ = unix.Close(proof.pidfd)
		}
	}()
	if !sameNetns(proof.inode, rt.inode) {
		return errors.New("domain sandbox replaced")
	}
	if err = r.domainOperations().recheck(ctx, r.CRI, proof, target); err != nil {
		return err
	}
	if ok, _ := r.verifyFreshAck(ctx, rt.gateway, &gw, next); !ok {
		return errors.New("DNS gateway acknowledgment unavailable")
	}
	factory, err := resolveBackend(r.Datapath, r.EBPFBackend)
	if err != nil {
		return err
	}
	// Require the protected DNS socket/redirect contract on every privileged
	// update, not only initial listener setup. Verify again after client nft
	// replacement, which must not erase or adopt the separate DNS table.
	if err = r.domainOperations().enter(target, func() error { return r.domainOperations().verifyRedirect(rt.resolver) }); err != nil {
		return err
	}
	gatewayMTU := cfg.MTU
	if err = r.domainOperations().enter(target, func() error { return r.domainOperations().measure(&next) }); err != nil {
		return err
	}
	previous := pod.Annotations[HashAnnotation]
	if err = r.domainOperations().program(ctx, target, &next, gatewayMTU, previous, false, factory, backendMode(r.Datapath)); err != nil {
		return r.poisonDomainReason(rt, target, &pod, quarantineDomainRouting)
	}
	if err = r.domainOperations().enter(target, func() error { return r.domainOperations().verifyRedirect(rt.resolver) }); err != nil {
		return r.poisonDomainReason(rt, target, &pod, quarantineDomainRedirect)
	}
	if err = r.patchDomainReady(ctx, &pod, next, backendMode(r.Datapath)); err != nil {
		return r.poisonDomainReason(rt, target, &pod, quarantineDomainPersistence)
	}
	if err = r.domainOperations().enter(target, r.domainOperations().marker); err != nil {
		return r.poisonDomainReason(rt, target, &pod, quarantineDomainRuntime)
	}
	return nil
}
func (r *Reconciler) poisonDomain(rt *domainRuntime, target *os.File, pod *corev1.Pod, cause error) error {
	return r.poisonDomainReason(rt, target, pod, reasonForDomainCause(cause))
}

func (r *Reconciler) poisonDomainReason(rt *domainRuntime, target *os.File, pod *corev1.Pod, reason string) error {
	rt.poisoned = true
	rt.retired.Store(true)
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fenceErr := r.domainOperations().quarantine(target, rt.podIP)
	rt.close()
	if fenceErr != nil {
		return errors.New("DNS compensation quarantine failed; workload unsafe and unavailable")
	}
	if _, err := r.recordQuarantine(cleanup, pod, reason); err != nil {
		return errors.Join(quarantineError(reason), err)
	}
	return quarantineError(reason)
}
func (r *Reconciler) syncDomain(ctx context.Context, rt *domainRuntime) {
	interval := r.domainOperations().interval
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rt.stop:
			return
		case <-timer.C:
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := rt.proxy.Sync(c)
			cancel()
			if err != nil {
				lock := r.domainLock(rt.uid)
				lock.Lock()
				if !rt.retired.Load() {
					pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: rt.name, Namespace: rt.namespace, UID: types.UID(rt.uid)}, Status: corev1.PodStatus{PodIP: rt.podIP.String()}}
					_ = r.poisonDomain(rt, rt.netns, pod, err)
				}
				lock.Unlock()
				return
			}
		}
	}
}
func (r *Reconciler) exchangeDomain(ctx context.Context, rt *domainRuntime, req *mdns.Msg, resolver, protocol string) (*mdns.Msg, error) {
	if (protocol != "udp" && protocol != "tcp") || resolver != net.JoinHostPort(rt.resolver.String(), "53") {
		return nil, errors.New("DNS exchange unauthorized")
	}
	lock := r.domainLock(rt.uid)
	lock.Lock()
	if rt.retired.Load() || rt.poisoned || rt.netns == nil {
		lock.Unlock()
		return nil, errors.New("DNS runtime retired")
	}
	fd, err := unix.Dup(int(rt.netns.Fd()))
	lock.Unlock()
	if err != nil {
		return nil, err
	}
	pinned := os.NewFile(uintptr(fd), "dns-exchange-netns")
	defer pinned.Close()
	// The namespace switch happens on the locked thread and ONLY opens the
	// upstream socket. All subsequent DNS I/O uses that already-marked FD;
	// no ordinary goroutine can accidentally create a host/agent-netns socket.
	var conn net.Conn
	err = r.domainOperations().enter(pinned, func() error {
		if err := r.domainOperations().verifyTarget(rt.podIP); err != nil {
			return err
		}
		control := func(network, address string, fd syscall.RawConn) error {
			var e error
			if x := fd.Control(func(v uintptr) {
				e = r.domainOperations().mark(int(v))
			}); x != nil {
				return x
			}
			return e
		}
		var err error
		conn, err = r.domainOperations().dial(ctx, protocol+"4", resolver, control)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := &mdns.Client{Net: protocol, Timeout: 3 * time.Second}
	result, _, err := client.ExchangeWithConnContext(ctx, req, &mdns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}
	return result, nil
}
