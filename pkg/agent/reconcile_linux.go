//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/skaldhall/ratatoskr/pkg/mtu"
	"github.com/skaldhall/ratatoskr/pkg/registration"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// clientMTU caps the inner tunnel by both the actual workload carrier and the
// gateway-advertised end-to-end limit. The gateway measurement alone does not
// describe the workload's CNI on a heterogeneous node.
func clientMTU(podMTU, gatewayMTU int, encryption string) (int, error) {
	if gatewayMTU < mtu.MinInnerMTU {
		return 0, fmt.Errorf("gateway effective MTU %d is below minimum %d", gatewayMTU, mtu.MinInnerMTU)
	}
	result, err := mtu.Compute(mtu.Params{
		PodMTU: podMTU, Underlay: mtu.IPv4,
		Encryption: mtu.Encryption(encryption), UpstreamMTU: gatewayMTU,
	})
	if err != nil {
		return 0, fmt.Errorf("compute workload eth0 tunnel MTU: %w", err)
	}
	return result.EffectiveMTU, nil
}

// completeClientMTU must execute inside the selected workload netns. It never
// substitutes a host link or a gateway pod's carrier MTU for eth0.
func completeClientMTU(cfg *datapath.ClientConfig) error {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("workload eth0 unavailable: %w", err)
	}
	cfg.MTU, err = clientMTU(link.Attrs().MTU, cfg.MTU, cfg.Encryption)
	return err
}

// Program constructs its backend only after entering the selected sandbox netns.
// The dummy marker is created LAST. Failure removes the marker and preserves the
// backend's unreachable fallback; callers must never publish ready on failure.
func Program(ctx context.Context, target *os.File, cfg *datapath.ClientConfig, gatewayMTU int, previous string, remove bool) error {
	return InNamespace(target, func() error {
		if !remove {
			// Re-read the carrier immediately before ApplyClient; changing it
			// after pre-registration requires a fresh reconciliation.
			computed := *cfg
			computed.MTU = gatewayMTU
			if err := completeClientMTU(&computed); err != nil {
				return err
			}
			if computed.MTU != cfg.MTU {
				return errors.New("workload eth0 MTU changed during programming; retry")
			}
		}
		backend, err := iproute.New()
		if err != nil {
			return err
		}
		defer backend.Close()
		marker, err := netlink.LinkByName(Marker)
		if err != nil && !isMissingLink(err) {
			return err
		}
		if remove {
			if marker != nil {
				if _, ok := marker.(*netlink.Dummy); !ok {
					return errors.New("readiness marker is not a dummy link")
				}
			}
			if marker == nil {
				return errors.New("refusing cleanup without owned marker")
			}
			if err := backend.RemoveClient(ctx, *cfg); err != nil {
				return err
			}
			return netlink.LinkDel(marker)
		}
		if marker != nil && previous == Hash(*cfg) {
			if _, ok := marker.(*netlink.Dummy); !ok {
				return errors.New("readiness marker is not a dummy link")
			}
			return nil
		} // restart adoption: preserve established tunnel and routes
		if marker != nil {
			if _, ok := marker.(*netlink.Dummy); !ok {
				return errors.New("readiness marker is not a dummy link")
			}
			if err := netlink.LinkDel(marker); err != nil {
				return err
			}
		}
		if err := backend.ApplyClient(ctx, *cfg); err != nil {
			return err
		}
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: Marker}}
		if err := netlink.LinkAdd(link); err != nil {
			return fmt.Errorf("readiness marker: %w", err)
		}
		// wait-init requires both a dummy device AND IFF_UP. Never publish a
		// down marker: it would leave restricted workloads blocked forever.
		created, err := netlink.LinkByName(Marker)
		if err != nil {
			_ = netlink.LinkDel(link)
			return fmt.Errorf("readiness marker lookup: %w", err)
		}
		if err := netlink.LinkSetUp(created); err != nil {
			_ = netlink.LinkDel(created)
			return fmt.Errorf("readiness marker up: %w", err)
		}
		return nil
	})
}
func isMissingLink(err error) bool { var e netlink.LinkNotFoundError; return errors.As(err, &e) }

type Reconciler struct {
	Client                  client.Client
	WatchClient             client.WithWatch
	CRI                     cri.RuntimeServiceClient
	Tokens                  TokenIssuer
	Node, OperatorNamespace string
	Log                     *slog.Logger
	Ready                   *atomic.Bool
}

func (r *Reconciler) Reconcile(ctx context.Context, pod *corev1.Pod) error {
	if pod.Spec.NodeName != r.Node || pod.Spec.HostNetwork || pod.UID == "" || pod.Status.PodIP == "" {
		return nil
	}
	existing := pod.Annotations[HashAnnotation]
	selected := pod.Labels[GatewayLabel] != "" && pod.DeletionTimestamp == nil
	if !selected && existing == "" {
		return nil
	}
	var cfg datapath.ClientConfig
	var err error
	removing := !selected
	if selected {
		var ns corev1.Namespace
		if err = r.Client.Get(ctx, types.NamespacedName{Name: pod.Namespace}, &ns); err != nil {
			return err
		}
		name := pod.Labels[GatewayLabel]
		gwNS := pod.Labels[GatewayNamespace]
		if a := pod.Annotations[GatewayNamespace]; a != "" {
			if gwNS != "" && gwNS != a {
				return errors.New("conflicting gateway namespace")
			}
			gwNS = a
		}
		if gwNS == "" {
			gwNS = r.OperatorNamespace
		}
		if gwNS == "" {
			return errors.New("OPERATOR_NAMESPACE required")
		}
		var gw api.EgressGateway
		if err = r.Client.Get(ctx, types.NamespacedName{Namespace: gwNS, Name: name}, &gw); err != nil {
			return err
		}
		var policies api.EgressPolicyList
		if err = r.Client.List(ctx, &policies, client.InNamespace(pod.Namespace)); err != nil {
			return err
		}
		cfg, err = Config(pod, &ns, &gw, policies.Items, r.OperatorNamespace)
		if err != nil {
			return err
		}
	} else {
		// A previously persisted non-secret config permits removing ONLY owned
		// rules in the same still-live sandbox, never guessed resources.
		if err = json.Unmarshal([]byte(pod.Annotations[ConfigAnnotation]), &cfg); err != nil || Hash(cfg) != existing || cfg.Identity.UID != string(pod.UID) || cfg.Identity.Namespace != pod.Namespace || cfg.Identity.Pod != pod.Name || cfg.PodIP.String() != pod.Status.PodIP {
			return errors.New("safe cleanup requires intact owned config and sandbox identity")
		}
	}
	if !removing && existing != "" {
		var old datapath.ClientConfig
		if json.Unmarshal([]byte(pod.Annotations[ConfigAnnotation]), &old) != nil || Hash(old) != existing || old.Identity.UID != string(pod.UID) || old.Encryption != cfg.Encryption {
			return errors.New("unsafe existing agent config or encryption transition")
		}
	}
	target, err := Sandbox(ctx, r.CRI, pod.Namespace, pod.Name, string(pod.UID), pod.Status.PodIP)
	if err != nil {
		return err
	}
	defer target.Close()
	gatewayMTU := cfg.MTU
	if !removing {
		if err = InNamespace(target, func() error { return completeClientMTU(&cfg) }); err != nil {
			return err
		}
	}
	if !removing && cfg.Encryption == "wireguard" && cfg.Endpoint.IsValid() && existing != Hash(cfg) {
		if r.Tokens == nil {
			return errors.New("TokenRequest client unavailable")
		}
		if existing != "" {
			var old datapath.ClientConfig
			if json.Unmarshal([]byte(pod.Annotations[ConfigAnnotation]), &old) != nil || old.Encryption != cfg.Encryption {
				return errors.New("unsafe encryption transition; refusing plaintext fallback")
			}
		}
		var publicKey string
		if err = InNamespace(target, func() error {
			backend, e := iproute.New()
			if e != nil {
				return e
			}
			defer backend.Close()
			// Block client traffic BEFORE requesting a token or contacting the
			// gateway. An unavailable registration must never leave plaintext
			// steering or a stale healthy endpoint in place.
			closed := cfg
			closed.Endpoint = netip.Addr{}
			closed.GatewayPublicKey = ""
			closed.RegistrationCACert = ""
			closed.WireGuardPort = 0
			if e = backend.ApplyClient(ctx, closed); e != nil {
				return e
			}
			publicKey, e = backend.PrepareClientWireGuard(ctx, cfg)
			return e
		}); err != nil {
			return err
		}
		// Registration MUST happen in host netns: host routing has no client WG
		// /32 policy, and its socket uses a TLS-pinned gateway PodIP, not DNS.
		if err = registration.RegisterClient(ctx, registration.ClientRequest{GatewayPodIP: cfg.Endpoint, RegistrationCACert: []byte(cfg.RegistrationCACert), ClientPublicKey: publicKey, AgentHostNetwork: true, TokenProvider: func(ctx context.Context) (string, error) { return podBoundToken(ctx, r.Tokens, pod) }}); err != nil {
			return fmt.Errorf("authenticate gateway peer: %w", err)
		}
	}
	if err = Program(ctx, target, &cfg, gatewayMTU, existing, removing); err != nil {
		return err
	}
	if removing {
		original := pod.DeepCopy()
		pod.Annotations = copyAnnotations(pod.Annotations)
		delete(pod.Annotations, HashAnnotation)
		delete(pod.Annotations, ConfigAnnotation)
		delete(pod.Annotations, ReadyAnnotation)
		return r.Client.Patch(ctx, pod, client.MergeFrom(original))
	}
	hash := Hash(cfg)
	if existing == hash && pod.Annotations[ReadyAnnotation] == "true" {
		return nil
	}
	original := pod.DeepCopy()
	pod.Annotations = copyAnnotations(pod.Annotations)
	pod.Annotations[HashAnnotation] = hash
	raw, _ := json.Marshal(cfg)
	pod.Annotations[ConfigAnnotation] = string(raw)
	pod.Annotations[ReadyAnnotation] = "true"
	return r.Client.Patch(ctx, pod, client.MergeFrom(original))
}
func copyAnnotations(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Run watches node Pods and gateway status; periodic full resync recovers missed
// events. The client makes live API reads rather than using a stale informer.
func (r *Reconciler) Run(ctx context.Context) error {
	if r.WatchClient == nil {
		return errors.New("watch client required")
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		watchCtx, cancel := context.WithCancel(ctx)
		pods, err := r.WatchClient.Watch(watchCtx, &corev1.PodList{}, client.MatchingFields{"spec.nodeName": r.Node})
		var gateways watch.Interface
		if err == nil {
			gateways, err = r.WatchClient.Watch(watchCtx, &api.EgressGatewayList{})
		}
		if err != nil {
			r.Log.Error("node API watch unavailable; retrying", "error", err)
		}
		syncErr := r.Sync(ctx)
		if r.Ready != nil {
			r.Ready.Store(syncErr == nil && err == nil)
		}
		if syncErr != nil {
			r.Log.Error("node reconciliation failed", "error", syncErr)
		}
		if err == nil {
			select {
			case <-ctx.Done():
			case <-ticker.C:
			case _, ok := <-pods.ResultChan():
				if !ok {
					r.Log.Warn("pod watch closed; reconnecting")
				}
			case _, ok := <-gateways.ResultChan():
				if !ok {
					r.Log.Warn("gateway watch closed; reconnecting")
				}
			}
		} else {
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
		cancel()
		if pods != nil {
			pods.Stop()
		}
		if gateways != nil {
			gateways.Stop()
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}
func (r *Reconciler) Sync(ctx context.Context) error {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.MatchingFields{"spec.nodeName": r.Node}); err != nil {
		return err
	}
	var count int
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Labels[GatewayLabel] == "" && p.Annotations[HashAnnotation] == "" {
			continue
		}
		if err := r.Reconcile(ctx, p); err != nil {
			r.Log.Error("pod reconciliation failed", "pod", p.Namespace+"/"+p.Name, "error", err)
			count++
		}
	}
	if count != 0 {
		return fmt.Errorf("%d pod reconciliations failed", count)
	}
	return nil
}
