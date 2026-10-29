package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// exclusions tracks provenance without emitting duplicate CIDRs. A more specific
// address may coexist with a cluster prefix so status retains its source.
type exclusions struct {
	entries map[string]api.EffectiveExclusion
}

func (e *exclusions) addCIDR(value, source string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
		return fmt.Errorf("invalid IPv4 CIDR for %s", source)
	}
	if e.entries == nil {
		e.entries = map[string]api.EffectiveExclusion{}
	}
	prefix = prefix.Masked()
	key := prefix.String()
	if _, ok := e.entries[key]; !ok {
		e.entries[key] = api.EffectiveExclusion{CIDR: key, Source: source}
	}
	return nil
}
func (e *exclusions) addIP(value, source string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() {
		return fmt.Errorf("invalid IPv4 %s address", source)
	}
	return e.addCIDR(netip.PrefixFrom(addr, 32).String(), source)
}
func (e *exclusions) configured(value, source string) (bool, error) {
	if strings.TrimSpace(value) == "" {
		return false, nil
	}
	for _, s := range strings.Split(value, ",") {
		if err := e.addCIDR(s, source); err != nil {
			return false, err
		}
	}
	return true, nil
}
func (e *exclusions) result() ([]api.EffectiveExclusion, error) {
	out := make([]api.EffectiveExclusion, 0, len(e.entries))
	for _, v := range e.entries {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CIDR == out[j].CIDR {
			return out[i].Source < out[j].Source
		}
		return out[i].CIDR < out[j].CIDR
	})
	if len(out) > 256 {
		return nil, fmt.Errorf("effective exclusions exceed API limit of 256")
	}
	return out, nil
}

// collectExclusions uses a direct APIReader for the optional ServiceCIDR API;
// clusters without that API fall back to configured SERVICE_CIDRS. Other
// discovery errors fail closed rather than being mistaken for absence.
func (r *GatewayReconciler) collectExclusions(ctx context.Context, gw *api.EgressGateway) ([]api.EffectiveExclusion, string, error) {
	var found exclusions
	if err := found.addCIDR("169.254.0.0/16", "linkLocal"); err != nil {
		return nil, "", err
	}
	podConfigured, err := found.configured(r.Options.PodCIDRs, "podCIDR")
	if err != nil {
		return nil, "", err
	}
	serviceConfigured, err := found.configured(r.Options.ServiceCIDRs, "serviceCIDR")
	if err != nil {
		return nil, "", err
	}
	if _, err := found.configured(r.Options.ExtraCIDRs, "extra"); err != nil {
		return nil, "", err
	}
	for _, cidr := range gw.Spec.Exclusions.ExtraCIDRs {
		if err := found.addCIDR(cidr, "extra"); err != nil {
			return nil, "", err
		}
	}
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return nil, "", fmt.Errorf("list Nodes: %w", err)
	}
	podDetected := false
	for _, node := range nodes.Items {
		nodeHasIPv4PodCIDR := false
		cidrs := node.Spec.PodCIDRs
		if len(cidrs) == 0 && node.Spec.PodCIDR != "" {
			cidrs = []string{node.Spec.PodCIDR}
		}
		for _, cidr := range cidrs {
			parsed, parseErr := netip.ParsePrefix(cidr)
			if parseErr != nil {
				return nil, "", fmt.Errorf("invalid Node PodCIDR")
			}
			if !parsed.Addr().Is4() {
				continue
			}
			if err := found.addCIDR(cidr, "podCIDR"); err != nil {
				return nil, "", err
			}
			podDetected = true
			nodeHasIPv4PodCIDR = true
		}
		if !nodeHasIPv4PodCIDR && !podConfigured {
			return nil, "", fmt.Errorf("node %s has no IPv4 PodCIDR and POD_CIDRS is not configured", node.Name)
		}
		for _, addr := range node.Status.Addresses {
			if addr.Type != corev1.NodeInternalIP && addr.Type != corev1.NodeExternalIP {
				continue
			}
			ip, e := netip.ParseAddr(addr.Address)
			if e != nil {
				return nil, "", fmt.Errorf("invalid Node IPv4 address")
			}
			if ip.Is4() {
				if err := found.addIP(addr.Address, "node"); err != nil {
					return nil, "", err
				}
			}
		}
	}
	if !podConfigured && !podDetected {
		return nil, "", fmt.Errorf("PodCIDRs unknown: configure POD_CIDRS or expose Node.spec.podCIDRs")
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var ranges networkingv1.ServiceCIDRList
	err = reader.List(ctx, &ranges)
	if err != nil && !meta.IsNoMatchError(err) && !errors.IsNotFound(err) {
		return nil, "", fmt.Errorf("list ServiceCIDRs: %w", err)
	}
	detected := false
	if err == nil {
		for _, sr := range ranges.Items {
			for _, cidr := range sr.Spec.CIDRs {
				p, e := netip.ParsePrefix(cidr)
				if e != nil {
					return nil, "", fmt.Errorf("invalid ServiceCIDR API prefix")
				}
				if p.Addr().Is4() {
					if e = found.addCIDR(cidr, "serviceCIDR"); e != nil {
						return nil, "", e
					}
					detected = true
				}
			}
		}
	}
	if !serviceConfigured && !detected {
		return nil, "", fmt.Errorf("ServiceCIDRs unknown: configure SERVICE_CIDRS or expose networking.k8s.io ServiceCIDRs")
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace), client.MatchingLabels{ownerUIDLabel: string(gw.UID)}); err != nil {
		return nil, "", fmt.Errorf("list gateway Pods: %w", err)
	}
	for _, p := range pods.Items {
		if p.Status.PodIP != "" {
			if err := found.addIP(p.Status.PodIP, "extra"); err != nil {
				return nil, "", err
			}
		}
	}
	for _, ep := range gw.Status.Endpoints {
		if ep.PodIP != "" {
			if err := found.addIP(ep.PodIP, "extra"); err != nil {
				return nil, "", err
			}
		}
	}
	for _, svc := range []types.NamespacedName{{Namespace: "default", Name: "kubernetes"}, {Namespace: "kube-system", Name: "kube-dns"}} {
		var service corev1.Service
		if err := r.Get(ctx, svc, &service); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return nil, "", fmt.Errorf("get discovery Service %s: %w", svc, err)
		}
		source := "apiserver"
		if svc.Name == "kube-dns" {
			source = "dns"
		}
		for _, ip := range append([]string{service.Spec.ClusterIP}, service.Spec.ClusterIPs...) {
			if ip == "" || ip == corev1.ClusterIPNone {
				continue
			}
			addr, e := netip.ParseAddr(ip)
			if e != nil {
				return nil, "", fmt.Errorf("invalid %s Service ClusterIP", source)
			}
			if addr.Is4() {
				if e = found.addIP(ip, source); e != nil {
					return nil, "", e
				}
			}
		}
		var slices discoveryv1.EndpointSliceList
		if err := r.List(ctx, &slices, client.InNamespace(svc.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
			return nil, "", fmt.Errorf("list %s EndpointSlices: %w", source, err)
		}
		for _, slice := range slices.Items {
			if slice.AddressType != discoveryv1.AddressTypeIPv4 {
				continue
			}
			for _, ep := range slice.Endpoints {
				for _, ip := range ep.Addresses {
					if err := found.addIP(ip, source); err != nil {
						return nil, "", err
					}
				}
			}
		}
		var endpoints corev1.Endpoints //nolint:staticcheck // Legacy endpoints remain a fallback on clusters not publishing API/DNS EndpointSlices.
		if err := r.Get(ctx, svc, &endpoints); err != nil {
			if !errors.IsNotFound(err) {
				return nil, "", fmt.Errorf("get %s Endpoints: %w", source, err)
			}
		} else {
			for _, subset := range endpoints.Subsets {
				for _, address := range append(subset.Addresses, subset.NotReadyAddresses...) {
					if address.IP != "" {
						ip, e := netip.ParseAddr(address.IP)
						if e != nil {
							return nil, "", fmt.Errorf("invalid %s Endpoint IP", source)
						}
						if ip.Is4() {
							if err := found.addIP(address.IP, source); err != nil {
								return nil, "", err
							}
						}
					}
				}
			}
		}
	}
	dnsIP := ""
	var dns corev1.Service
	if err := r.Get(ctx, types.NamespacedName{Namespace: "kube-system", Name: "kube-dns"}, &dns); err == nil {
		ip, e := netip.ParseAddr(dns.Spec.ClusterIP)
		if e == nil && ip.Is4() && !ip.IsUnspecified() {
			dnsIP = ip.String()
		}
	} else if !errors.IsNotFound(err) {
		return nil, "", fmt.Errorf("get cluster DNS Service: %w", err)
	}
	result, err := found.result()
	return result, dnsIP, err
}
