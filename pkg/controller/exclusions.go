package controller

import (
	"context"
	goerrors "errors"
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

// exclusionFailure identifies a fixed public remediation category. The cause
// stays internal: API/provider errors may contain credentials or private URLs.
type exclusionFailure struct {
	code  string
	cause error
}

func (e *exclusionFailure) Error() string { return e.code }
func (e *exclusionFailure) Unwrap() error { return e.cause }
func exclusionError(code string, cause error) error {
	return &exclusionFailure{code: code, cause: cause}
}

// exclusionAdvice is deliberately authored text: never format the wrapped
// error, Node name, CIDR, Secret or an API response into public status/Events.
func exclusionAdvice(err error) (code, message string) {
	var failure *exclusionFailure
	if !goerrors.As(err, &failure) {
		return "Unknown", "Exclusion discovery blocked; check controller access to cluster network resources."
	}
	switch failure.code {
	case "PodCIDRsMissing":
		return failure.code, "Pod CIDRs unknown; set Helm exclusions.podCIDRs or populate Node.spec.podCIDRs."
	case "NodePodCIDRMissing":
		return failure.code, "A Node lacks an IPv4 PodCIDR; set Helm exclusions.podCIDRs or populate Node.spec.podCIDRs."
	case "ServiceCIDRsMissing":
		return failure.code, "Service CIDRs unknown; set Helm exclusions.serviceCIDRs or enable networking.k8s.io ServiceCIDR discovery."
	case "ConfiguredCIDRInvalid":
		return failure.code, "Invalid configured CIDR; check Helm exclusions.podCIDRs, exclusions.serviceCIDRs, exclusions.extraCIDRs and Gateway spec.exclusions.extraCIDRs."
	case "NodeCIDRInvalid":
		return failure.code, "Node PodCIDR or address invalid; correct Node.spec.podCIDRs or Node.status.addresses."
	case "ServiceCIDRInvalid":
		return failure.code, "ServiceCIDR API contains invalid CIDRs; correct networking.k8s.io ServiceCIDR data."
	case "EndpointAddressInvalid":
		return failure.code, "Discovered Pod, Service or EndpointSlice IPv4 address invalid; correct cluster network objects."
	case "ExclusionsTooMany":
		return failure.code, "Too many effective exclusions; reduce configured extra CIDRs or discovered ranges."
	case "NodesReadDenied":
		return failure.code, "Cannot list Nodes for exclusions; grant the controller nodes list permission."
	case "ServiceCIDRsReadDenied":
		return failure.code, "Cannot list ServiceCIDRs for exclusions; grant the controller networking.k8s.io servicecidrs list permission."
	case "PodsReadDenied":
		return failure.code, "Cannot list owned Gateway Pods for exclusions; grant the controller pods list permission."
	case "ServiceReadDenied":
		return failure.code, "Cannot GET Kubernetes API or kube-dns Services; grant the controller services get permission."
	case "EndpointSlicesReadDenied":
		return failure.code, "Cannot list Kubernetes API or kube-dns EndpointSlices; grant the controller discovery.k8s.io endpointslices list permission."
	case "NodesReadFailed":
		return failure.code, "Cannot list Nodes for exclusions; check API availability and controller nodes access."
	case "ServiceCIDRsReadFailed":
		return failure.code, "Cannot list ServiceCIDRs for exclusions; check API availability or set Helm exclusions.serviceCIDRs if this API is not served."
	case "PodsReadFailed":
		return failure.code, "Cannot list owned Gateway Pods for exclusions; check API availability and controller pods access."
	case "ServiceReadFailed":
		return failure.code, "Cannot GET Kubernetes API or kube-dns Services; check API availability and controller services access."
	case "EndpointSlicesReadFailed":
		return failure.code, "Cannot list Kubernetes API or kube-dns EndpointSlices; check API availability and controller endpointslices access."
	default:
		return "Unknown", "Exclusion discovery blocked; check controller access to cluster network resources."
	}
}

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

func exclusionReadError(resource string, err error) error {
	// Callers pass fixed resource names only. The wrapped API error never enters
	// status, logs or Events, but remains inspectable by internal callers.
	if errors.IsForbidden(err) || errors.IsUnauthorized(err) {
		return exclusionError(resource+"ReadDenied", err)
	}
	return exclusionError(resource+"ReadFailed", err)
}

// collectExclusions uses a direct APIReader for the optional ServiceCIDR API;
// clusters without that API fall back to configured SERVICE_CIDRS. Other
// discovery errors fail closed rather than being mistaken for absence.
func (r *GatewayReconciler) collectExclusions(ctx context.Context, gw *api.EgressGateway) ([]api.EffectiveExclusion, string, error) {
	var found exclusions
	if err := found.addCIDR("169.254.0.0/16", "linkLocal"); err != nil {
		return nil, "", exclusionError("ConfiguredCIDRInvalid", err)
	}
	podConfigured, err := found.configured(r.Options.PodCIDRs, "podCIDR")
	if err != nil {
		return nil, "", exclusionError("ConfiguredCIDRInvalid", err)
	}
	serviceConfigured, err := found.configured(r.Options.ServiceCIDRs, "serviceCIDR")
	if err != nil {
		return nil, "", exclusionError("ConfiguredCIDRInvalid", err)
	}
	if _, err := found.configured(r.Options.ExtraCIDRs, "extra"); err != nil {
		return nil, "", exclusionError("ConfiguredCIDRInvalid", err)
	}
	for _, cidr := range gw.Spec.Exclusions.ExtraCIDRs {
		if err := found.addCIDR(cidr, "extra"); err != nil {
			return nil, "", exclusionError("ConfiguredCIDRInvalid", err)
		}
	}
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return nil, "", exclusionReadError("Nodes", err)
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
				return nil, "", exclusionError("NodeCIDRInvalid", parseErr)
			}
			if !parsed.Addr().Is4() {
				continue
			}
			if err := found.addCIDR(cidr, "podCIDR"); err != nil {
				return nil, "", exclusionError("NodeCIDRInvalid", err)
			}
			podDetected = true
			nodeHasIPv4PodCIDR = true
		}
		if !nodeHasIPv4PodCIDR && !podConfigured {
			return nil, "", exclusionError("NodePodCIDRMissing", nil)
		}
		for _, addr := range node.Status.Addresses {
			if addr.Type != corev1.NodeInternalIP && addr.Type != corev1.NodeExternalIP {
				continue
			}
			ip, e := netip.ParseAddr(addr.Address)
			if e != nil {
				return nil, "", exclusionError("NodeCIDRInvalid", e)
			}
			if ip.Is4() {
				if err := found.addIP(addr.Address, "node"); err != nil {
					return nil, "", exclusionError("NodeCIDRInvalid", err)
				}
			}
		}
	}
	if !podConfigured && !podDetected {
		return nil, "", exclusionError("PodCIDRsMissing", nil)
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var ranges networkingv1.ServiceCIDRList
	err = reader.List(ctx, &ranges)
	if err != nil && !meta.IsNoMatchError(err) && !errors.IsNotFound(err) {
		return nil, "", exclusionReadError("ServiceCIDRs", err)
	}
	detected := false
	if err == nil {
		for _, sr := range ranges.Items {
			for _, cidr := range sr.Spec.CIDRs {
				p, e := netip.ParsePrefix(cidr)
				if e != nil {
					return nil, "", exclusionError("ServiceCIDRInvalid", e)
				}
				if p.Addr().Is4() {
					if e = found.addCIDR(cidr, "serviceCIDR"); e != nil {
						return nil, "", exclusionError("ServiceCIDRInvalid", e)
					}
					detected = true
				}
			}
		}
	}
	if !serviceConfigured && !detected {
		return nil, "", exclusionError("ServiceCIDRsMissing", nil)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace), client.MatchingLabels{ownerUIDLabel: string(gw.UID)}); err != nil {
		return nil, "", exclusionReadError("Pods", err)
	}
	for _, p := range pods.Items {
		if p.Status.PodIP != "" {
			if err := found.addIP(p.Status.PodIP, "extra"); err != nil {
				return nil, "", exclusionError("EndpointAddressInvalid", err)
			}
		}
	}
	for _, ep := range gw.Status.Endpoints {
		if ep.PodIP != "" {
			if err := found.addIP(ep.PodIP, "extra"); err != nil {
				return nil, "", exclusionError("EndpointAddressInvalid", err)
			}
		}
	}
	for _, svc := range []types.NamespacedName{{Namespace: "default", Name: "kubernetes"}, {Namespace: "kube-system", Name: "kube-dns"}} {
		var service corev1.Service
		if err := r.Get(ctx, svc, &service); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return nil, "", exclusionReadError("Service", err)
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
				return nil, "", exclusionError("EndpointAddressInvalid", e)
			}
			if addr.Is4() {
				if e = found.addIP(ip, source); e != nil {
					return nil, "", exclusionError("EndpointAddressInvalid", e)
				}
			}
		}
		var slices discoveryv1.EndpointSliceList
		if err := r.List(ctx, &slices, client.InNamespace(svc.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
			return nil, "", exclusionReadError("EndpointSlices", err)
		}
		for _, slice := range slices.Items {
			if slice.AddressType != discoveryv1.AddressTypeIPv4 {
				continue
			}
			for _, ep := range slice.Endpoints {
				for _, ip := range ep.Addresses {
					if err := found.addIP(ip, source); err != nil {
						return nil, "", exclusionError("EndpointAddressInvalid", err)
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
		return nil, "", exclusionReadError("Service", err)
	}
	result, err := found.result()
	if err != nil {
		return nil, "", exclusionError("ExclusionsTooMany", err)
	}
	return result, dnsIP, nil
}
