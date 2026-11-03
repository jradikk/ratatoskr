package controller

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/netip"
	"os"
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
	case "ClusterDNSInvalid":
		return failure.code, "Configured dns.clusterIP is not usable IPv4; set Helm dns.clusterIP to the cluster DNS Service or reachable NodeLocal IPv4 address."
	case "ClusterDNSUnknown":
		return failure.code, "Cluster DNS IPv4 unavailable; configure Helm dns.clusterIP or ensure controller Pod ClusterFirst DNS nameserver is reachable."
	case "ExclusionsTooMany":
		return failure.code, "Too many effective exclusions; reduce configured extra CIDRs or discovered ranges."
	case "NodesReadDenied":
		return failure.code, "Cannot list Nodes for exclusions; grant the controller nodes list permission."
	case "ServiceCIDRsReadDenied":
		return failure.code, "Cannot list ServiceCIDRs for exclusions; grant the controller networking.k8s.io servicecidrs list permission."
	case "PodsReadDenied":
		return failure.code, "Cannot list owned Gateway Pods for exclusions; grant the controller pods list permission."
	case "ServiceReadDenied":
		return failure.code, "Cannot GET Kubernetes API Service or list labeled DNS Services; grant controller services get/list permission."
	case "EndpointSlicesReadDenied":
		return failure.code, "Cannot list Kubernetes API or discovered DNS EndpointSlices; grant controller discovery.k8s.io endpointslices list permission."
	case "NodesReadFailed":
		return failure.code, "Cannot list Nodes for exclusions; check API availability and controller nodes access."
	case "ServiceCIDRsReadFailed":
		return failure.code, "Cannot list ServiceCIDRs for exclusions; check API availability or set Helm exclusions.serviceCIDRs if this API is not served."
	case "PodsReadFailed":
		return failure.code, "Cannot list owned Gateway Pods for exclusions; check API availability and controller pods access."
	case "ServiceReadFailed":
		return failure.code, "Cannot GET Kubernetes API Service or list labeled DNS Services; check API availability and controller services access."
	case "EndpointSlicesReadFailed":
		return failure.code, "Cannot list Kubernetes API or discovered DNS EndpointSlices; check API availability and controller endpointslices access."
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

// addServiceAndSlices preserves direct access to discovered Service VIPs and
// endpoint IPs. API read errors remain typed without exporting API response text.
func (e *exclusions) addServiceAndSlices(ctx context.Context, r *GatewayReconciler, svc *corev1.Service, source string) error {
	for _, value := range append([]string{svc.Spec.ClusterIP}, svc.Spec.ClusterIPs...) {
		if value == "" || value == corev1.ClusterIPNone {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return exclusionError("EndpointAddressInvalid", err)
		}
		if ip.Is4() {
			if err := e.addIP(value, source); err != nil {
				return exclusionError("EndpointAddressInvalid", err)
			}
		}
	}
	var slices discoveryv1.EndpointSliceList
	if err := r.List(ctx, &slices, client.InNamespace(svc.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
		return exclusionReadError("EndpointSlices", err)
	}
	for _, slice := range slices.Items {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			for _, value := range endpoint.Addresses {
				if err := e.addIP(value, source); err != nil {
					return exclusionError("EndpointAddressInvalid", err)
				}
			}
		}
	}
	return nil
}

// clusterDNSAddress uses the operator's explicit service/node-local resolver
// override when provided; otherwise it reads the controller Pod's ClusterFirst
// resolver configuration. Never assume a DNS Service name or namespace.
func (r *GatewayReconciler) clusterDNSAddress() (netip.Addr, error) {
	if r.Options.ClusterDNSIP != "" {
		ip, err := netip.ParseAddr(r.Options.ClusterDNSIP)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return netip.Addr{}, exclusionError("ClusterDNSInvalid", err)
		}
		return ip, nil
	}
	read := r.ReadResolver
	if read == nil {
		read = func() ([]byte, error) { return os.ReadFile("/etc/resolv.conf") }
	}
	raw, err := read()
	if err != nil || len(raw) > 16<<10 {
		return netip.Addr{}, exclusionError("ClusterDNSUnknown", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		ip, parseErr := netip.ParseAddr(fields[1])
		if parseErr == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() {
			return ip, nil
		}
	}
	return netip.Addr{}, exclusionError("ClusterDNSUnknown", nil)
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
	// The Kubernetes API Service name is fixed by Kubernetes. Cluster DNS is
	// intentionally not: CoreDNS can live in another namespace/name, and a
	// kubelet-configured NodeLocal resolver may not have a Service at all.
	var apiService corev1.Service
	apiKey := types.NamespacedName{Namespace: "default", Name: "kubernetes"}
	if err := r.Get(ctx, apiKey, &apiService); err != nil {
		if !errors.IsNotFound(err) {
			return nil, "", exclusionReadError("Service", err)
		}
	} else if err := found.addServiceAndSlices(ctx, r, &apiService, "apiserver"); err != nil {
		return nil, "", err
	}
	resolver, err := r.clusterDNSAddress()
	if err != nil {
		return nil, "", err
	}
	if err := found.addIP(resolver.String(), "dns"); err != nil {
		return nil, "", exclusionError("EndpointAddressInvalid", err)
	}
	// Discover DNS Services by common kube-dns/CoreDNS labels, without relying
	// on their namespace or name. Do not pick an unrelated candidate as the
	// resolver: kubelet's actual controller Pod resolver/explicit override wins.
	var services corev1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return nil, "", exclusionReadError("Service", err)
	}
	for i := range services.Items {
		svc := &services.Items[i]
		if svc.Labels["k8s-app"] != "kube-dns" && svc.Labels["app.kubernetes.io/name"] != "coredns" && svc.Labels["app.kubernetes.io/name"] != "kube-dns" {
			continue
		}
		if err := found.addServiceAndSlices(ctx, r, svc, "dns"); err != nil {
			return nil, "", err
		}
	}
	result, err := found.result()
	if err != nil {
		return nil, "", exclusionError("ExclusionsTooMany", err)
	}
	return result, resolver.String(), nil
}
