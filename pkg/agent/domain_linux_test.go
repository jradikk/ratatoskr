//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/skaldhall/ratatoskr/pkg/fqdn"
	"github.com/skaldhall/ratatoskr/pkg/policy"

	mdns "github.com/miekg/dns"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
)

func domainFixture(t *testing.T, mode string) (*Reconciler, *corev1.Pod, *api.EgressGateway, *api.EgressPolicy, datapath.ClientConfig, *os.File, sandboxProof, *atomic.Int32) {
	t.Helper()
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "apps", UID: "workload-uid", ResourceVersion: "1", Labels: map[string]string{GatewayLabel: "g"}}, Spec: corev1.PodSpec{NodeName: "node", DNSPolicy: corev1.DNSNone, DNSConfig: &corev1.PodDNSConfig{Nameservers: []string{"192.0.2.53"}}}, Status: corev1.PodStatus{PodIP: "10.1.0.2"}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}
	gw := &api.EgressGateway{ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "operator", UID: "gateway-uid", Generation: 1}, Spec: api.EgressGatewaySpec{DNS: api.DNSConfig{Mode: "gateway"}, AllowedNamespaces: api.AllowedNamespacesSpec{NamespaceSelector: &metav1.LabelSelector{}}}, Status: api.EgressGatewayStatus{ObservedGeneration: 1, GatewayID: 7, MTU: api.GatewayMTUStatus{EffectiveMTU: 1400}, Endpoints: []api.GatewayEndpoint{{PodIP: "10.2.0.3", UpstreamHealthy: true}}}}
	pol := &api.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "domains", Namespace: "apps", UID: "policy-uid", Generation: 1}, Spec: api.EgressPolicySpec{GatewayRef: api.GatewayReference{Name: "g"}, Mode: mode, WorkloadSelector: metav1.LabelSelector{}, Rules: []api.EgressRule{{Domains: []api.DomainSelector{{MatchName: "example.test"}}, Ports: []api.EgressPort{{Protocol: "TCP", Port: 443}}}}}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "g-dns", Namespace: "operator", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "192.0.2.53", Ports: []corev1.ServicePort{{Protocol: corev1.ProtocolUDP, Port: 53, TargetPort: intstr.FromInt32(1053)}, {Protocol: corev1.ProtocolTCP, Port: 53, TargetPort: intstr.FromInt32(1053)}}}}
	rawGateway := `{"gatewayID":7,"mtu":1400,"clients":["10.1.0.2"]}`
	digest := sha256.Sum256([]byte(rawGateway))
	gw.Status.Endpoints[0].PodName = "gateway-pod"
	gw.Status.Endpoints[0].PodUID = "gateway-pod-uid"
	gw.Status.Endpoints[0].AppliedClientConfigHash = hex.EncodeToString(digest[:])
	gatewayPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway-pod", Namespace: "operator", UID: "gateway-pod-uid"}, Status: corev1.PodStatus{PodIP: "10.2.0.3"}}
	gatewayConfig := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "operator", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}}, Data: map[string]string{"gateway.json": rawGateway}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(p, ns, gw, pol, svc, gatewayPod, gatewayConfig).Build()
	r := &Reconciler{Client: c, Node: "node", OperatorNamespace: "operator", Datapath: "iproute"}
	cfg, err := Config(p, ns, gw, []api.EgressPolicy{*pol}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if err = restoreDomainConfig(p, &cfg, *pol, "iproute"); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "fake-ns")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var inode unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &inode); err != nil {
		t.Fatal(err)
	}
	proof := sandboxProof{inode: inode, pidfd: -1}
	programs := &atomic.Int32{}
	r.domainOps = &domainOperations{mark: func(int) error { return nil }, own: func(context.Context) error { return nil }, enter: func(_ *os.File, run func() error) error { return run() }, verifyTarget: func(netip.Addr) error { return nil }, recheck: func(context.Context, cri.RuntimeServiceClient, sandboxProof, *os.File) error { return nil }, sandbox: func(context.Context, cri.RuntimeServiceClient, string, string, string, string) (*os.File, sandboxProof, error) {
		fd, e := unix.Dup(int(f.Fd()))
		return os.NewFile(uintptr(fd), "fake-proof"), proof, e
	}, program: func(context.Context, *os.File, *datapath.ClientConfig, int, string, bool, BackendFactory, string) error {
		programs.Add(1)
		return nil
	}, quarantine: func(*os.File, netip.Addr) error { return nil }, redirect: func(netip.Addr) error { return nil }, verifyRedirect: func(netip.Addr) error { return nil }, removeRedirect: func(netip.Addr) error { return nil }, listenPacket: func(string, string) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") }, listen: func(string, string) (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") }, interval: time.Hour}
	return r, p, gw, pol, cfg, f, proof, programs
}
func TestConfigAssignsPersistedDomainIdentity(t *testing.T) {
	r, p, gw, pol, cfg, _, _, _ := domainFixture(t, "include")
	if cfg.DomainPolicyUID != string(pol.UID) || cfg.DomainPolicyGeneration != 1 {
		t.Fatal("domain policy identity missing")
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: p.Namespace}}
	pol.UID = ""
	if _, err := Config(p, ns, gw, []api.EgressPolicy{*pol}, r.OperatorNamespace); err == nil {
		t.Fatal("fake policy UID accepted")
	}
	pol.UID = "policy-uid"
	pol.Generation = 0
	if _, err := Config(p, ns, gw, []api.EgressPolicy{*pol}, r.OperatorNamespace); err == nil {
		t.Fatal("unpersisted generation accepted")
	}
}
func TestRetainedIncludeRestoreAndExplicitGenerationReplacement(t *testing.T) {
	_, p, _, pol, cfg, _, _, _ := domainFixture(t, "include")
	old := cfg
	old.DomainState = []datapath.DomainBinding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 1, Retained: true}}
	p.Annotations = map[string]string{ConfigAnnotation: mustJSON(t, old), HashAnnotation: HashForMode(old, "iproute")}
	if err := restoreDomainConfig(p, &cfg, *pol, "iproute"); err != nil {
		t.Fatal(err)
	}
	if len(cfg.DomainState) != 1 || len(cfg.Policy.Rules) != 1 {
		t.Fatal("restart discarded retained include route")
	}
	cfg.DomainPolicyGeneration = 2
	cfg.DomainState = nil
	pol.Generation = 2
	if err := restoreDomainConfig(p, &cfg, *pol, "iproute"); err != nil {
		t.Fatal(err)
	}
	if len(cfg.DomainState) != 0 {
		t.Fatal("explicit policy replacement retained previous generation")
	}
}
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type patchFailure struct{ client.Client }

func (p patchFailure) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	return errors.New("synthetic ambiguous API patch")
}
func TestDomainAnnotationFailureQuarantinesBeforeNoSuccessfulResponse(t *testing.T) {
	r, p, _, _, cfg, f, _, programs := domainFixture(t, "include")
	rt := &domainRuntime{uid: string(p.UID), namespace: p.Namespace, name: p.Name, policyUID: cfg.DomainPolicyUID, generation: 1, podIP: cfg.PodIP, netns: f, stop: make(chan struct{}), done: make(chan struct{})}
	r.putDomain(rt.uid, rt)
	r.Client = patchFailure{r.Client}
	fences := 0
	r.domainOps.quarantine = func(*os.File, netip.Addr) error { fences++; return nil }
	lock := r.domainLock(rt.uid)
	lock.Lock()
	err := r.patchDomainReady(context.Background(), p, cfg, "iproute")
	if err != nil {
		err = r.poisonDomain(rt, f, p, err)
	}
	lock.Unlock()
	if err == nil || fences != 1 || !rt.poisoned || !rt.retired.Load() || programs.Load() != 0 {
		t.Fatal("failed persistence did not quarantine runtime")
	}
	select {
	case <-rt.done:
	case <-time.After(time.Second):
		t.Fatal("retired resources not closed")
	}
}
func TestPerUIDLocksIndependentAndRetirementNoDeadlock(t *testing.T) {
	r := &Reconciler{}
	first := r.domainLock("one")
	second := r.domainLock("two")
	first.Lock()
	done := make(chan struct{})
	go func() { second.Lock(); defer second.Unlock(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unrelated workload serialized globally")
	}
	first.Unlock()
	rt := &domainRuntime{uid: "one", stop: make(chan struct{}), done: make(chan struct{})}
	r.putDomain("one", rt)
	first.Lock()
	r.retireDomain("one")
	first.Unlock()
	select {
	case <-rt.done:
	case <-time.After(time.Second):
		t.Fatal("retirement waited on callback while holding lock")
	}
	if !rt.retired.Load() {
		t.Fatal("callback epoch still active")
	}
}
func TestDomainLocalUDPAndTCPForwardUseControlAndBeforeReplyApply(t *testing.T) {
	r, p, gw, pol, cfg, f, proof, programs := domainFixture(t, "include")
	// Fake external resolver on loopback only. Production sockets still use the
	// injected verified target-netns operation and mandatory control callback.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	udpServer := &mdns.Server{PacketConn: packet, Net: "udp", Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		answer := new(mdns.Msg).SetReply(q)
		rr, _ := mdns.NewRR("example.test. 60 IN A 203.0.113.8")
		answer.Answer = []mdns.RR{rr}
		_ = w.WriteMsg(answer)
	})}
	tcpServer := &mdns.Server{Listener: listener, Net: "tcp", Handler: udpServer.Handler}
	readyUDP := make(chan struct{})
	readyTCP := make(chan struct{})
	udpServer.NotifyStartedFunc = func() { close(readyUDP) }
	tcpServer.NotifyStartedFunc = func() { close(readyTCP) }
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	defer func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() }()
	<-readyUDP
	<-readyTCP
	var controlCalls atomic.Int32
	r.domainOps.mark = func(int) error { controlCalls.Add(1); return nil }
	r.domainOps.dial = func(ctx context.Context, network, address string, control func(string, string, syscall.RawConn) error) (net.Conn, error) {
		// Exercise real SO_MARK on unprivileged own socket may be denied; raw fake
		// callback supplied below proves invocation while fake dial remains local.
		if control == nil || address != "192.0.2.53:53" {
			t.Fatal("unauthorized/unmarked resolver dial")
		}
		return (&net.Dialer{Control: control}).DialContext(ctx, network, listener.Addr().String())
	}
	fences := &atomic.Int32{}
	r.domainOps.quarantine = func(*os.File, netip.Addr) error { fences.Add(1); return nil }
	lock := r.domainLock(string(p.UID))
	lock.Lock()
	if err = r.startDomain(context.Background(), p, gw, pol, cfg, f, proof, "iproute"); err != nil {
		lock.Unlock()
		t.Fatal(err)
	}
	lock.Unlock()
	defer r.closeDomains()
	rt := r.domainRuntime(string(p.UID))
	_ = rt
	// Servers' handler closures read rt.proxy; replacement above is before requests.
	for _, network := range []string{"udp", "tcp"} {
		before := programs.Load()
		serverAddress := rt.udp.LocalAddr().String()
		if network == "tcp" {
			serverAddress = rt.tcp.Addr().String()
		}
		answer, _, err := (&mdns.Client{Net: network, Timeout: time.Second}).Exchange(new(mdns.Msg).SetQuestion("example.test.", mdns.TypeA), serverAddress)
		if err != nil || answer.Rcode != mdns.RcodeSuccess || programs.Load() <= before {
			t.Fatal("local DNS answer escaped sync callback")
		}
	}
	if controlCalls.Load() != 2 {
		t.Fatal("both UDP and TCP did not use target controlled dial")
	}
	lock.Lock()
	r.Client = patchFailure{r.Client}
	lock.Unlock()
	answer, _, err := (&mdns.Client{Net: "udp", Timeout: time.Second}).Exchange(new(mdns.Msg).SetQuestion("example.test.", mdns.TypeA), rt.udp.LocalAddr().String())
	if err == nil && answer.Rcode == mdns.RcodeSuccess {
		t.Fatal("successful answer escaped failed annotation persistence")
	}
	if fences.Load() != 1 || !rt.retired.Load() {
		t.Fatal("DNS failed persistence did not quarantine/retire")
	}
}

var _ sync.Locker = (*sync.Mutex)(nil)

func TestDomainSyncExpiryIncludeRetainedExcludeWithdrawn(t *testing.T) {
	for _, mode := range []string{"include", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			r, p, gw, pol, cfg, f, proof, _ := domainFixture(t, mode)
			lock := r.domainLock(string(p.UID))
			lock.Lock()
			if err := r.patchDomainReady(context.Background(), p, cfg, "iproute"); err != nil {
				lock.Unlock()
				t.Fatal(err)
			}
			lock.Unlock()
			var inode unix.Stat_t
			if err := unix.Fstat(int(f.Fd()), &inode); err != nil {
				t.Fatal(err)
			}
			rt := &domainRuntime{uid: string(p.UID), namespace: p.Namespace, name: p.Name, policyUID: cfg.DomainPolicyUID, generation: 1, podIP: cfg.PodIP, gateway: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, gatewayUID: string(gw.UID), resolver: netip.MustParseAddr("192.0.2.53"), netns: f, inode: inode, stop: make(chan struct{}), done: make(chan struct{})}
			r.putDomain(rt.uid, rt)
			defer r.closeDomains()
			rules, err := policy.DomainRules(pol.Spec)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1000, 0)
			learned := datapath.DomainBinding{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 1001, Retained: mode == "include"}
			rt.proxy, err = fqdn.New(fqdn.Options{Mode: mode, Rules: rules, Resolver: "192.0.2.53:53", Restore: []fqdn.Binding{learned}, Clock: func() time.Time { return now }, Apply: func(ctx context.Context, u fqdn.Update) error { return r.applyDomain(ctx, rt, u) }})
			if err != nil {
				t.Fatal(err)
			}
			if err = rt.proxy.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * time.Second)
			if err = rt.proxy.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			var current corev1.Pod
			if err = r.Client.Get(context.Background(), client.ObjectKeyFromObject(p), &current); err != nil {
				t.Fatal(err)
			}
			var persisted datapath.ClientConfig
			if err = json.Unmarshal([]byte(current.Annotations[ConfigAnnotation]), &persisted); err != nil {
				t.Fatal(err)
			}
			if HashForMode(persisted, "iproute") != current.Annotations[HashAnnotation] {
				t.Fatal("persisted compiled state hash mismatch")
			}
			if mode == "include" && len(persisted.DomainState) != 1 {
				t.Fatal("expired include protection lost")
			}
			if mode == "exclude" && len(persisted.DomainState) != 0 {
				t.Fatal("expired exclude bypass remained")
			}
			_ = proof
		})
	}
}
func TestStaleQueuedPodRefreshCannotOverwriteLearnedAnnotation(t *testing.T) {
	r, p, _, _, cfg, _, _, _ := domainFixture(t, "include")
	old := p.DeepCopy()
	cfg.DomainState = []datapath.DomainBinding{{Rule: 0, Address: netip.MustParseAddr("203.0.113.8"), ExpiresAt: 1, Retained: true}}
	if err := r.patchDomainReady(context.Background(), p, cfg, "iproute"); err != nil {
		t.Fatal(err)
	}
	r.putDomain(string(p.UID), &domainRuntime{})
	if err := r.refreshDomainPod(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if old.Annotations[HashAnnotation] != HashForMode(cfg, "iproute") {
		t.Fatal("queued old Pod discarded newly learned retained state")
	}
}

func TestApplyDomainRejectsRetiredCallbackWithoutMutation(t *testing.T) {
	r, p, _, _, cfg, f, _, programs := domainFixture(t, "include")
	rt := &domainRuntime{uid: string(p.UID), netns: f, podIP: cfg.PodIP}
	rt.retired.Store(true)
	if err := r.applyDomain(context.Background(), rt, fqdn.Update{}); err == nil {
		t.Fatal("retired callback accepted")
	}
	if programs.Load() != 0 {
		t.Fatal("retired callback mutated backend")
	}
}
func TestDomainConcurrentApplyAndQueuedReconcileNoLockInversion(t *testing.T) {
	r, p, _, _, cfg, f, _, _ := domainFixture(t, "include")
	if err := r.patchDomainReady(context.Background(), p, cfg, "iproute"); err != nil {
		t.Fatal(err)
	}
	rt := &domainRuntime{uid: string(p.UID), podIP: cfg.PodIP, netns: f, stop: make(chan struct{}), done: make(chan struct{})}
	r.putDomain(rt.uid, rt)
	lock := r.domainLock(rt.uid)
	started := make(chan struct{})
	done := make(chan struct{})
	lock.Lock()
	go func() { close(started); _ = r.applyDomain(context.Background(), rt, fqdn.Update{}); close(done) }()
	<-started
	// Reconcile-side state refresh does not call Proxy.Snapshot while perUID locked.
	if err := r.refreshDomainPod(context.Background(), p); err != nil {
		lock.Unlock()
		t.Fatal(err)
	}
	lock.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback/reconciliation lock inversion")
	}
	r.closeDomains()
}
