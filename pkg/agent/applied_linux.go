//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The controller proves Pod→ReplicaSet→Deployment→Gateway ownership before
// publishing status.PodUID. The agent trusts that owner attestation but GETs
// the live Pod and checks identity, lifecycle and selected endpoint again.
func gatewayEndpointPod(ctx context.Context, reader client.Reader, gw *api.EgressGateway, endpointIP netip.Addr, endpointUID string) error {
	if gw == nil || gw.UID == "" || endpointUID == "" || !endpointIP.Is4() {
		return errors.New("gateway or endpoint ownership identity missing")
	}
	name := ""
	count := 0
	for _, ep := range gw.Status.Endpoints {
		if ep.PodIP == endpointIP.String() {
			count++
			name = ep.PodName
		}
	}
	if count != 1 || name == "" {
		return errors.New("selected gateway endpoint ambiguous or missing Pod name")
	}
	var pod corev1.Pod
	if err := reader.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, &pod); err != nil {
		return fmt.Errorf("GET selected gateway Pod: %w", err)
	}
	if string(pod.UID) != endpointUID || pod.Namespace != gw.Namespace || pod.Name != name || pod.Status.PodIP != endpointIP.String() || pod.DeletionTimestamp != nil || pod.Spec.HostNetwork {
		return errors.New("selected gateway Pod identity differs from controller-attested endpoint")
	}
	return nil
}

// checkAppliedRaw compares the exact ConfigMap gateway.json bytes with the
// gateway-process-applied hash. Decoding serves membership validation only:
// reserializing would change the hash and weaken projection race detection.
func checkAppliedRaw(raw, hash string, config datapath.ClientConfig, endpoint netip.Addr) error {
	if raw == "" || len(raw) > 1<<20 || len(hash) != 64 || strings.ToLower(hash) != hash {
		return errors.New("applied gateway config hash or raw bytes unavailable")
	}
	digest := sha256.Sum256([]byte(raw))
	if hex.EncodeToString(digest[:]) != hash {
		return errors.New("gateway projected config differs from applied hash")
	}
	var gw datapath.GatewayConfig
	if err := json.Unmarshal([]byte(raw), &gw); err != nil {
		return fmt.Errorf("decode gateway config: %w", err)
	}
	// gateway.json is rendered before the Downward API supplies PodIP. Validate
	// the rest against the authenticated selected endpoint without changing raw
	// bytes used for the applied hash.
	validated := gw
	if !validated.PodIP.IsValid() {
		validated.PodIP = endpoint
	}
	if err := validated.Validate(); err != nil {
		return fmt.Errorf("validate gateway config: %w", err)
	}
	// Rendered gateway.json may have PodIP unset/null and is completed from
	// the Pod's Downward API in the gateway process. The selected endpoint Pod
	// itself, not an invalid JSON PodIP, supplies that authenticated binding.
	if gw.PodIP.IsValid() && gw.PodIP != endpoint {
		return errors.New("gateway config PodIP differs from selected endpoint")
	}
	if gw.GatewayID != config.GatewayID || gw.Encryption != config.Encryption {
		return errors.New("gateway config ID or encryption differs from selected client")
	}
	for _, ip := range gw.Clients {
		if ip == config.PodIP {
			return nil
		}
	}
	return errors.New("selected client PodIP absent from applied gateway config")
}

func (r *Reconciler) appliedGateway(ctx context.Context, gw *api.EgressGateway, cfg datapath.ClientConfig, endpointUID, appliedHash string) error {
	if !cfg.Endpoint.IsValid() || endpointUID == "" || appliedHash == "" {
		return errors.New("selected gateway endpoint has no applied-client acknowledgement")
	}
	if err := gatewayEndpointPod(ctx, r.Client, gw, cfg.Endpoint, endpointUID); err != nil {
		return err
	}
	var cm corev1.ConfigMap
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &cm); err != nil {
		return fmt.Errorf("GET owner-controlled gateway ConfigMap: %w", err)
	}
	if cm.DeletionTimestamp != nil || !metav1.IsControlledBy(&cm, gw) {
		return errors.New("gateway ConfigMap owner UID differs from gateway")
	}
	return checkAppliedRaw(cm.Data["gateway.json"], appliedHash, cfg, cfg.Endpoint)
}
