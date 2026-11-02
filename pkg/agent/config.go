package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/affinity"
	"github.com/skaldhall/ratatoskr/pkg/policy"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const Prefix = "ratatoskr.skaldhall.io/"
const GatewayLabel = Prefix + "gateway"
const GatewayNamespace = Prefix + "gateway-namespace"
const HashAnnotation = Prefix + "agent-hash"
const BackendAnnotation = Prefix + "agent-backend"
const ConfigAnnotation = Prefix + "agent-config"
const ReadyAnnotation = Prefix + "datapath-ready"
const Marker = "rtk-ready"

func Config(p *corev1.Pod, ns *corev1.Namespace, gw *api.EgressGateway, policies []api.EgressPolicy, operatorNS string) (datapath.ClientConfig, error) {
	c := datapath.ClientConfig{}
	if p.Spec.HostNetwork || p.UID == "" || p.Spec.NodeName == "" || p.Labels[GatewayLabel] != gw.Name {
		return c, errors.New("pod is not an eligible selected workload")
	}
	target := p.Labels[GatewayNamespace]
	if a := p.Annotations[GatewayNamespace]; a != "" {
		if target != "" && a != target {
			return c, errors.New("conflicting gateway namespace")
		}
		target = a
	}
	if target == "" {
		target = operatorNS
	}
	if target != gw.Namespace {
		return c, errors.New("gateway namespace mismatch")
	}
	if gw.Spec.AllowedNamespaces.NamespaceSelector == nil || ns.Name != p.Namespace {
		return c, errors.New("namespace not authorized")
	}
	selector, err := metav1.LabelSelectorAsSelector(gw.Spec.AllowedNamespaces.NamespaceSelector)
	if err != nil || !selector.Matches(labels.Set(ns.Labels)) {
		return c, errors.New("namespace not authorized")
	}
	if gw.Status.ObservedGeneration != gw.Generation || gw.Status.GatewayID == 0 || gw.Spec.FailMode != "" && gw.Spec.FailMode != "closed" {
		return c, errors.New("gateway status stale or unsupported")
	}
	ip, err := netip.ParseAddr(p.Status.PodIP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() {
		return c, errors.New("pod IPv4 unavailable")
	}
	c = datapath.ClientConfig{PodIP: ip, GatewayID: gw.Status.GatewayID, MTU: int(gw.Status.MTU.EffectiveMTU), Encryption: gw.Spec.Encryption, AllowCloudMetadata: gw.Spec.Exclusions.AllowCloudMetadata, Identity: datapath.Identity{Namespace: p.Namespace, Pod: p.Name, UID: string(p.UID)}}
	if c.Encryption == "" {
		c.Encryption = "none"
	}
	for _, e := range gw.Status.EffectiveExclusions {
		v, err := netip.ParsePrefix(e.CIDR)
		if err != nil || !v.Addr().Is4() {
			return c, fmt.Errorf("invalid effective exclusion %q", e.CIDR)
		}
		c.Exclusions = append(c.Exclusions, v.Masked())
	}
	sort.Slice(c.Exclusions, func(i, j int) bool { return c.Exclusions[i].String() < c.Exclusions[j].String() })
	for _, pol := range policies {
		sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.WorkloadSelector)
		if err != nil {
			return c, err
		}
		if !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		target := pol.Spec.GatewayRef.Namespace
		if target == "" {
			target = operatorNS
		}
		if pol.Spec.GatewayRef.Name != gw.Name || target != gw.Namespace {
			return c, errors.New("matching policy points to another gateway")
		}
		if c.Identity.Policy != "" {
			return c, errors.New("multiple matching policies")
		}
		c.Policy, err = policy.Compile(pol.Spec)
		if err != nil {
			return c, err
		}
		c.Identity.Policy = pol.Name
	}
	// Only controller-reported healthy PodIP endpoints participate. Never use a
	// Service ClusterIP or accept a malformed healthy status as a bypass.
	healthy := make([]netip.Addr, 0, len(gw.Status.Endpoints))
	identities := make(map[netip.Addr]api.GatewayEndpoint, len(gw.Status.Endpoints))
	for _, e := range gw.Status.Endpoints {
		if !e.UpstreamHealthy {
			continue
		}
		v, parseErr := netip.ParseAddr(e.PodIP)
		if parseErr != nil || !v.Is4() || v.IsUnspecified() || v.IsMulticast() || v.IsLoopback() || v.IsLinkLocalUnicast() || v == ip {
			return c, fmt.Errorf("invalid healthy gateway PodIP %q", e.PodIP)
		}
		if previous, exists := identities[v]; exists {
			if c.Encryption == "wireguard" && (previous.WireguardPublicKey != e.WireguardPublicKey || previous.RegistrationCACert != e.RegistrationCACert) {
				return c, fmt.Errorf("conflicting WireGuard identity for gateway PodIP %s", v)
			}
			continue
		}
		if c.Encryption == "wireguard" && (e.WireguardPublicKey == "" || e.RegistrationCACert == "") {
			return c, errors.New("healthy WireGuard endpoint missing authenticated public identity")
		}
		healthy = append(healthy, v)
		identities[v] = e
	}
	if len(healthy) > 0 {
		c.Endpoint, err = affinity.Select(string(p.UID), healthy)
		if err != nil {
			return c, fmt.Errorf("select healthy gateway PodIP: %w", err)
		}
		if c.Encryption == "wireguard" {
			selected := identities[c.Endpoint]
			c.GatewayPublicKey = selected.WireguardPublicKey
			c.RegistrationCACert = selected.RegistrationCACert
			c.WireGuardPort = datapath.WireGuardPortDefault
		}
	} else if c.MTU == 0 {
		// The controller clears measured MTU when every gateway is unhealthy.
		// No usable tunnel is possible: validate a conservative closed-only
		// fallback instead of treating transient health as authorization loss
		// and permanently quarantining DNS/API access. A healthy endpoint
		// still requires its measured MTU and fails closed if absent.
		c.MTU = 576
	}

	return c, c.Validate()
}
func Hash(c datapath.ClientConfig) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// HashForMode binds the authorized config to the selected backend. iproute
// keeps the M5 digest so existing healthy routes remain adoptable.
func HashForMode(c datapath.ClientConfig, mode string) string {
	if backendMode(mode) == "iproute" {
		return Hash(c)
	}
	sum := sha256.Sum256([]byte(backendMode(mode) + ":" + Hash(c)))
	return hex.EncodeToString(sum[:])
}
