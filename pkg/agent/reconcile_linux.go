//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/iproute"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Program constructs its backend only after entering the selected sandbox netns.
// The dummy marker is created LAST. Failure removes the marker and preserves the
// backend's unreachable fallback; callers must never publish ready on failure.
func Program(ctx context.Context, target *os.File, cfg datapath.ClientConfig, previous string, remove bool) error {
	return InNamespace(target, func() error {
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
			if marker == nil {
				return errors.New("refusing cleanup without owned marker")
			}
			if err := backend.RemoveClient(ctx, cfg); err != nil {
				return err
			}
			return netlink.LinkDel(marker)
		}
		if marker != nil && previous == Hash(cfg) {
			return nil
		} // restart adoption: preserve established tunnel and routes
		if marker != nil {
			if err := netlink.LinkDel(marker); err != nil {
				return err
			}
		}
		if err := backend.ApplyClient(ctx, cfg); err != nil {
			return err
		}
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: Marker}}
		if err := netlink.LinkAdd(link); err != nil {
			return fmt.Errorf("readiness marker: %w", err)
		}
		return nil
	})
}
func isMissingLink(err error) bool { var e netlink.LinkNotFoundError; return errors.As(err, &e) }

type Reconciler struct {
	Client                  client.Client
	CRI                     cri.RuntimeServiceClient
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
	target, err := Sandbox(ctx, r.CRI, pod.Namespace, pod.Name, string(pod.UID), pod.Status.PodIP)
	if err != nil {
		return err
	}
	defer target.Close()
	if err = Program(ctx, target, cfg, existing, removing); err != nil {
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

// Run performs bounded API resyncs; each iteration observes both pod and
// gateway status changes (including endpoint health), without stale informer data.
func (r *Reconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		err := r.Sync(ctx)
		if r.Ready != nil {
			r.Ready.Store(err == nil)
		}
		if err != nil {
			r.Log.Error("node reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
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
