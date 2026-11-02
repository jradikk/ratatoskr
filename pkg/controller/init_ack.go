package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const initAppliedAckAnnotation = "ratatoskr.skaldhall.io/gateway-applied-ack"

type initAppliedAck struct {
	WorkloadUID   string `json:"workloadUID"`
	WorkloadPodIP string `json:"workloadPodIP"`
	GatewayUID    string `json:"gatewayUID"`
	GatewayID     uint32 `json:"gatewayID"`
	GatewayPodUID string `json:"gatewayPodUID"`
	GatewayPodIP  string `json:"gatewayPodIP"`
	ConfigHash    string `json:"configHash"`
}

func appliedInitAck(gw *api.EgressGateway, p *corev1.Pod, raw string) string {
	if gw == nil || p == nil || p.UID == "" || gw.UID == "" || gw.Status.ObservedGeneration != gw.Generation || gw.Status.GatewayID == 0 || len(gw.Status.Endpoints) == 0 || raw == "" {
		return ""
	}
	clientIP, err := netip.ParseAddr(p.Status.PodIP)
	if err != nil || !clientIP.Is4() || clientIP.IsUnspecified() {
		return ""
	}
	var desired datapath.ClientConfig
	if err = json.Unmarshal([]byte(p.Annotations["ratatoskr.skaldhall.io/client-config"]), &desired); err != nil || !desired.Endpoint.Is4() || desired.GatewayID != gw.Status.GatewayID {
		return ""
	}
	// At admission the config omits UID/IP; the bound workload UID and actual
	// PodIP are verified here, not inferred from a stale admission snapshot.
	if desired.Identity.Namespace != p.Namespace || desired.Identity.Pod != p.Name || desired.Identity.UID != "" && desired.Identity.UID != string(p.UID) || desired.PodIP.IsValid() && desired.PodIP != clientIP {
		return ""
	}
	var config datapath.GatewayConfig
	if err = json.Unmarshal([]byte(raw), &config); err != nil || config.GatewayID != gw.Status.GatewayID {
		return ""
	}
	inClients := false
	for _, ip := range config.Clients {
		if ip == clientIP {
			inClients = true
			break
		}
	}
	if !inClients {
		return ""
	}
	count := 0
	var selected api.GatewayEndpoint
	for _, ep := range gw.Status.Endpoints {
		if ep.PodIP == desired.Endpoint.String() {
			count++
			selected = ep
		}
	}
	if count != 1 || !selected.UpstreamHealthy || selected.PodUID == "" || selected.AppliedClientConfigHash == "" || selected.PodName == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(raw))
	if selected.AppliedClientConfigHash != hex.EncodeToString(digest[:]) {
		return ""
	}
	ack := initAppliedAck{WorkloadUID: string(p.UID), WorkloadPodIP: clientIP.String(), GatewayUID: string(gw.UID), GatewayID: gw.Status.GatewayID, GatewayPodUID: selected.PodUID, GatewayPodIP: selected.PodIP, ConfigHash: selected.AppliedClientConfigHash}
	data, err := json.Marshal(ack)
	if err != nil {
		return ""
	}
	return string(data)
}

func (r *GatewayReconciler) reconcileInitAppliedAck(ctx context.Context, gw *api.EgressGateway, raw string) error {
	if r.Options.Driver == "agent" || gw == nil {
		return nil
	}
	namespaces := corev1.NamespaceList{}
	if err := r.List(ctx, &namespaces); err != nil {
		return err
	}
	var selector labels.Selector
	if gw.Spec.AllowedNamespaces.NamespaceSelector != nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(gw.Spec.AllowedNamespaces.NamespaceSelector)
		if err != nil {
			return err
		}
	}
	for _, ns := range namespaces.Items {
		allowed := raw != "" && selector != nil && selector.Matches(labels.Set(ns.Labels))
		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.InNamespace(ns.Name), client.MatchingLabels{GatewayLabel: gw.Name}); err != nil {
			return err
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Spec.HostNetwork || p.Labels[IdentityLabel] != "" {
				continue
			}
			target := p.Labels[GatewayNamespace]
			if target == "" {
				target = p.Annotations[GatewayNamespace]
			}
			if target == "" {
				target = r.Options.OperatorNamespace
			}
			if target != gw.Namespace {
				continue
			}
			if _, ok := p.Annotations[initAppliedAckAnnotation]; !ok {
				continue
			}
			desired := ""
			if p.DeletionTimestamp == nil && allowed {
				desired = appliedInitAck(gw, p, raw)
			}
			if p.Annotations[initAppliedAckAnnotation] == desired {
				continue
			}
			old := p.DeepCopy()
			p.Annotations[initAppliedAckAnnotation] = desired
			if err := r.Patch(ctx, p, client.MergeFrom(old)); err != nil {
				return fmt.Errorf("patch init applied ack: %w", err)
			}
		}
	}
	return nil
}
