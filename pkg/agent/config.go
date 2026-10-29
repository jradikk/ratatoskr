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
	"github.com/skaldhall/ratatoskr/pkg/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const Prefix = "ratatoskr.skaldhall.io/"
const GatewayLabel = Prefix + "gateway"
const GatewayNamespace = Prefix + "gateway-namespace"
const HashAnnotation = Prefix + "agent-hash"
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
	if c.Encryption == "wireguard" {
		return c, errors.New("agent WireGuard registration requires in-memory token API; refusing plaintext fallback")
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
	for _, e := range gw.Status.Endpoints {
		v, err := netip.ParseAddr(e.PodIP)
		if e.UpstreamHealthy && err == nil && v.Is4() && !v.IsUnspecified() && !v.IsMulticast() && v != ip {
			c.Endpoint = v
			break
		}
	}
	return c, c.Validate()
}
func Hash(c datapath.ClientConfig) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
