// Package webhook implements fail-closed Ratatoskr admission and TLS bootstrap.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	prefix           = "ratatoskr.skaldhall.io/"
	GatewayLabel     = prefix + "gateway"
	GatewayNamespace = prefix + "gateway-namespace"
	ConfigAnnotation = prefix + "client-config"
	ReadyAnnotation  = prefix + "datapath-ready"
	initName         = "ratatoskr-init"
	configVolume     = "ratatoskr-client-config"
)

type Handler struct {
	Client               client.Client
	Namespace, InitImage string
}

func denied(err error) admission.Response { return admission.Denied(err.Error()) }
func (h *Handler) MutatePod(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create {
		return admission.Allowed("not a pod create")
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denied(err)
	}
	name := pod.Labels[GatewayLabel]
	if name == "" {
		return admission.Allowed("not opted in")
	}
	if h.InitImage == "" {
		return denied(fmt.Errorf("INIT_IMAGE is required for opted-in pods"))
	}
	if pod.Spec.HostNetwork {
		return denied(fmt.Errorf("hostNetwork pods cannot use Ratatoskr"))
	}
	if len(pod.Spec.InitContainers) > 0 {
		for _, c := range pod.Spec.InitContainers {
			if c.Name == initName {
				return denied(fmt.Errorf("reserved init container %s already exists", initName))
			}
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == configVolume {
			return denied(fmt.Errorf("reserved volume %s already exists", configVolume))
		}
	}
	ns := req.Namespace
	if ns == "" {
		ns = pod.Namespace
	}
	if ns == "" {
		return denied(fmt.Errorf("pod namespace is required"))
	}
	gatewayNS := pod.Labels[GatewayNamespace]
	if annotation := pod.Annotations[GatewayNamespace]; annotation != "" {
		if gatewayNS != "" && gatewayNS != annotation {
			return denied(fmt.Errorf("conflicting gateway namespace label and annotation"))
		}
		gatewayNS = annotation
	}
	if gatewayNS == "" {
		gatewayNS = h.Namespace
	}
	if gatewayNS == "" {
		return denied(fmt.Errorf("NAMESPACE is required to resolve gateway"))
	}
	var gateway v1alpha1.EgressGateway
	if err := h.Client.Get(ctx, types.NamespacedName{Namespace: gatewayNS, Name: name}, &gateway); err != nil {
		return denied(fmt.Errorf("resolve EgressGateway: %w", err))
	}
	if err := supportedGateway(&gateway); err != nil {
		return denied(err)
	}
	var namespace corev1.Namespace
	if err := h.Client.Get(ctx, types.NamespacedName{Name: ns}, &namespace); err != nil {
		return denied(fmt.Errorf("resolve workload namespace: %w", err))
	}
	if gateway.Spec.AllowedNamespaces.NamespaceSelector == nil {
		return denied(fmt.Errorf("gateway denies all namespaces: namespaceSelector is absent"))
	}
	selector, err := metav1.LabelSelectorAsSelector(gateway.Spec.AllowedNamespaces.NamespaceSelector)
	if err != nil {
		return denied(fmt.Errorf("invalid namespaceSelector: %w", err))
	}
	if !selector.Matches(labels.Set(namespace.Labels)) {
		return denied(fmt.Errorf("namespace %s is not allowed by gateway", ns))
	}
	if gateway.Status.GatewayID == 0 || gateway.Status.GatewayID > 0xffffff {
		return denied(fmt.Errorf("gatewayID not allocated; retry after gateway reconciliation"))
	}
	matches, err := h.matchingPolicies(ctx, ns, pod.Labels)
	if err != nil {
		return denied(err)
	}
	if len(matches) > 1 {
		return denied(fmt.Errorf("multiple EgressPolicies match pod: %v", matches))
	}
	if len(matches) == 1 {
		return denied(fmt.Errorf("EgressPolicy %s matches pod; selective policies require M3", matches[0]))
	}
	cfg := datapath.ClientConfig{GatewayID: gateway.Status.GatewayID, MTU: 0, Encryption: "none", Identity: datapath.Identity{Namespace: ns, Pod: pod.Name}, Exclusions: []netip.Prefix{}}
	for _, e := range gateway.Status.EffectiveExclusions {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil || !p.Addr().Is4() {
			return denied(fmt.Errorf("gateway has invalid effective exclusion %q", e.CIDR))
		}
		cfg.Exclusions = append(cfg.Exclusions, p)
	}
	for _, endpoint := range gateway.Status.Endpoints {
		ip, err := netip.ParseAddr(endpoint.PodIP)
		if endpoint.UpstreamHealthy && err == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() {
			cfg.Endpoint = ip
			break
		}
	}
	// An absent endpoint is intentional: the init backend installs an unreachable route.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return denied(err)
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[ConfigAnnotation] = string(raw)
	pod.Annotations[ReadyAnnotation] = "pending"
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: configVolume, VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{{Path: "client.json", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.annotations['" + ConfigAnnotation + "']"}}}}}})
	privileged := false
	pod.Spec.InitContainers = append([]corev1.Container{{Name: initName, Image: h.InitImage, Args: []string{"-config=/var/run/ratatoskr/client.json"}, SecurityContext: &corev1.SecurityContext{Privileged: &privileged, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}}, Env: []corev1.EnvVar{
		{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
		{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
		{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
	}, VolumeMounts: []corev1.VolumeMount{{Name: configVolume, MountPath: "/var/run/ratatoskr", ReadOnly: true}}}}, pod.Spec.InitContainers...)
	mutated, err := json.Marshal(&pod)
	if err != nil {
		return denied(err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, mutated)
}
func supportedGateway(g *v1alpha1.EgressGateway) error {
	if g.Spec.Encryption != "" && g.Spec.Encryption != "none" {
		return fmt.Errorf("gateway encryption %q is not implemented in M2", g.Spec.Encryption)
	}
	if g.Spec.DNS.Mode != "" && g.Spec.DNS.Mode != "cluster" {
		return fmt.Errorf("gateway DNS mode %q is not implemented in M2", g.Spec.DNS.Mode)
	}
	if g.Spec.Upstream.Type != "openvpn" {
		return fmt.Errorf("gateway upstream %q is not implemented in M2", g.Spec.Upstream.Type)
	}
	if g.Spec.FailMode != "" && g.Spec.FailMode != "closed" {
		return fmt.Errorf("gateway failMode must be closed")
	}
	return nil
}
func (h *Handler) matchingPolicies(ctx context.Context, ns string, podLabels map[string]string) ([]string, error) {
	var list v1alpha1.EgressPolicyList
	if err := h.Client.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("list EgressPolicies: %w", err)
	}
	var matches []string
	for _, p := range list.Items {
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.WorkloadSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid selector on EgressPolicy %s: %w", p.Name, err)
		}
		if sel.Matches(labels.Set(podLabels)) {
			matches = append(matches, p.Name)
		}
	}
	return matches, nil
}
func (h *Handler) Validate(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return admission.Allowed("not create/update")
	}
	switch req.Kind.Kind {
	case "Pod":
		if req.Operation != admissionv1.Update {
			return admission.Allowed("pod create handled by mutator")
		}
		var pod, old corev1.Pod
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			return denied(err)
		}
		if err := json.Unmarshal(req.OldObject.Raw, &old); err != nil {
			return denied(err)
		}
		if old.Status.Phase == corev1.PodRunning && (old.Labels[GatewayLabel] != pod.Labels[GatewayLabel] || namespaceOverride(&old) != namespaceOverride(&pod)) {
			return denied(fmt.Errorf("running pod gateway opt-in and namespace are immutable"))
		}
	case "EgressGateway":
		var g v1alpha1.EgressGateway
		if err := json.Unmarshal(req.Object.Raw, &g); err != nil {
			return denied(err)
		}
		if g.Spec.AllowedNamespaces.NamespaceSelector != nil {
			if _, err := metav1.LabelSelectorAsSelector(g.Spec.AllowedNamespaces.NamespaceSelector); err != nil {
				return denied(fmt.Errorf("invalid allowedNamespaces.namespaceSelector: %w", err))
			}
		}
		if err := supportedGateway(&g); err != nil {
			return denied(err)
		}
	case "EgressPolicy":
		var policy v1alpha1.EgressPolicy
		if err := json.Unmarshal(req.Object.Raw, &policy); err != nil {
			return denied(err)
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.WorkloadSelector)
		if err != nil {
			return denied(fmt.Errorf("invalid workloadSelector: %w", err))
		}
		ns := req.Namespace
		if ns == "" {
			ns = policy.Namespace
		}
		if ns == "" {
			return denied(fmt.Errorf("policy namespace required"))
		}
		var pods corev1.PodList
		if err = h.Client.List(ctx, &pods, client.InNamespace(ns)); err != nil {
			return denied(err)
		}
		for _, p := range pods.Items {
			if !selector.Matches(labels.Set(p.Labels)) {
				continue
			}
			matches, err := h.matchingPolicies(ctx, ns, p.Labels)
			if err != nil {
				return denied(err)
			}
			for _, other := range matches {
				if other != policy.Name {
					return denied(fmt.Errorf("policy %s overlaps %s on pod %s", policy.Name, other, p.Name))
				}
			}
		}
	default:
		return denied(fmt.Errorf("unexpected admission kind %q", req.Kind.Kind))
	}
	return admission.Allowed("valid")
}
func namespaceOverride(p *corev1.Pod) string {
	return p.Labels[GatewayNamespace] + "/" + p.Annotations[GatewayNamespace]
}
