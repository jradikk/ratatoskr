package webhook

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
)

// gatewayDNSIP returns the dedicated gateway Service ClusterIP, never a gateway
// PodIP. Both the Service and a healthy gateway endpoint must exist for gateway
// DNS; otherwise admitting the workload would risk node DNS fallback.
func (h *Handler) gatewayDNSIP(ctx context.Context, pod *corev1.Pod) (netip.Addr, error) {
	gatewayNS := pod.Labels[GatewayNamespace]
	if gatewayNS == "" {
		gatewayNS = pod.Annotations[GatewayNamespace]
	}
	if gatewayNS == "" {
		gatewayNS = h.Namespace
	}
	var gateway v1alpha1.EgressGateway
	if err := h.Client.Get(ctx, types.NamespacedName{Namespace: gatewayNS, Name: pod.Labels[GatewayLabel]}, &gateway); err != nil {
		return netip.Addr{}, fmt.Errorf("resolve gateway DNS mode: %w", err)
	}
	if gateway.Spec.DNS.Mode != "gateway" {
		return netip.Addr{}, nil
	}
	healthy := false
	for _, endpoint := range gateway.Status.Endpoints {
		ip, err := netip.ParseAddr(endpoint.PodIP)
		if endpoint.UpstreamHealthy && err == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() {
			healthy = true
			break
		}
	}
	if !healthy {
		return netip.Addr{}, fmt.Errorf("gateway DNS requires a healthy gateway PodIP endpoint")
	}
	var service corev1.Service
	if err := h.Client.Get(ctx, types.NamespacedName{Namespace: gatewayNS, Name: gateway.Name + "-dns"}, &service); err != nil {
		return netip.Addr{}, fmt.Errorf("gateway DNS Service unavailable: %w", err)
	}
	ip, err := netip.ParseAddr(service.Spec.ClusterIP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("gateway DNS Service has no valid IPv4 ClusterIP")
	}
	return ip, nil
}
func (h *Handler) gatewaySearches(namespace string) ([]string, error) {
	domain := strings.TrimSuffix(h.ClusterDomain, ".")
	if namespace == "" || domain == "" {
		return nil, fmt.Errorf("workload namespace and CLUSTER_DOMAIN required for gateway DNS")
	}
	return []string{namespace + ".svc." + domain, "svc." + domain, domain}, nil
}
func (h *Handler) mutateGatewayDNS(ctx context.Context, admissionNamespace string, pod *corev1.Pod) error {
	ip, err := h.gatewayDNSIP(ctx, pod)
	if err != nil {
		return err
	}
	if !ip.IsValid() {
		return nil
	}
	ns := admissionNamespace
	if ns == "" {
		ns = pod.Namespace
	}
	searches, err := h.gatewaySearches(ns)
	if err != nil {
		return err
	}
	options := []corev1.PodDNSConfigOption{}
	if pod.Spec.DNSConfig != nil {
		seen := map[string]bool{}
		for _, v := range searches {
			seen[v] = true
		}
		for _, v := range pod.Spec.DNSConfig.Searches {
			if !seen[v] {
				searches = append(searches, v)
				seen[v] = true
			}
		}
		for _, v := range pod.Spec.DNSConfig.Options {
			if v.Name != "ndots" {
				options = append(options, v)
			}
		}
	}
	ndots := "5"
	options = append(options, corev1.PodDNSConfigOption{Name: "ndots", Value: &ndots})
	pod.Spec.DNSPolicy = corev1.DNSNone
	pod.Spec.DNSConfig = &corev1.PodDNSConfig{Nameservers: []string{ip.String()}, Searches: searches, Options: options}
	return nil
}
func (h *Handler) validateGatewayDNS(ctx context.Context, admissionNamespace string, pod *corev1.Pod) error {
	ip, err := h.gatewayDNSIP(ctx, pod)
	if err != nil {
		return err
	}
	if !ip.IsValid() {
		return nil
	}
	ns := admissionNamespace
	if ns == "" {
		ns = pod.Namespace
	}
	required, err := h.gatewaySearches(ns)
	if err != nil {
		return err
	}
	dns := pod.Spec.DNSConfig
	if pod.Spec.DNSPolicy != corev1.DNSNone || dns == nil || len(dns.Nameservers) != 1 || dns.Nameservers[0] != ip.String() {
		return fmt.Errorf("gateway DNS must use the dedicated Service ClusterIP without node DNS fallback")
	}
	if len(dns.Searches) < len(required) {
		return fmt.Errorf("gateway DNS cluster search domains missing")
	}
	for i, v := range required {
		if dns.Searches[i] != v {
			return fmt.Errorf("gateway DNS cluster search domains invalid")
		}
	}
	ndots := 0
	for _, option := range dns.Options {
		if option.Name == "ndots" {
			ndots++
			if option.Value == nil || *option.Value != "5" {
				return fmt.Errorf("gateway DNS ndots must be 5")
			}
		}
	}
	if ndots != 1 {
		return fmt.Errorf("gateway DNS ndots must be 5")
	}
	return nil
}
