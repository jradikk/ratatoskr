// Package webhook implements fail-closed Ratatoskr admission and TLS bootstrap.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	policycompiler "github.com/skaldhall/ratatoskr/pkg/policy"
)

const (
	prefix           = "ratatoskr.skaldhall.io/"
	GatewayLabel     = prefix + "gateway"
	GatewayNamespace = prefix + "gateway-namespace"
	ConfigAnnotation = prefix + "client-config"
	ReadyAnnotation  = prefix + "datapath-ready"
	initName         = "ratatoskr-init"
	configVolume     = "ratatoskr-client-config"
	wgTokenVolume    = "ratatoskr-wg-token"             // #nosec G101 -- volume name, not a token value.
	wgTokenAudience  = "ratatoskr.skaldhall.io/gateway" // #nosec G101 -- projected token audience, not a credential.
	wgTokenMount     = "/var/run/ratatoskr/wg-token"    // #nosec G101 -- fixed mount path, not token bytes.
)

type Handler struct {
	Client                              client.Client
	Namespace, InitImage, ClusterDomain string
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
		if v.Name == configVolume || v.Name == wgTokenVolume {
			return denied(fmt.Errorf("reserved volume %s already exists", v.Name))
		}
	}
	for _, c := range append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...) {
		for _, mount := range c.VolumeMounts {
			if mount.Name == wgTokenVolume || mount.MountPath == wgTokenMount {
				return denied(fmt.Errorf("reserved WireGuard token mount already exists"))
			}
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		for _, mount := range c.VolumeMounts {
			if mount.Name == wgTokenVolume || mount.MountPath == wgTokenMount {
				return denied(fmt.Errorf("reserved WireGuard token mount already exists"))
			}
		}
	}
	cfg, err := h.clientConfig(ctx, req.Namespace, &pod)
	if err != nil {
		return denied(err)
	}
	if err := h.mutateGatewayDNS(ctx, req.Namespace, &pod); err != nil {
		return denied(err)
	}
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
	if cfg.Encryption == "wireguard" {
		injectWireGuardToken(&pod)
	}
	mutated, err := json.Marshal(&pod)
	if err != nil {
		return denied(err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, mutated)
}

// clientConfig is shared by mutation and CREATE validation so admission never
// trusts an annotation for gateway authorization or datapath parameters.
func (h *Handler) clientConfig(ctx context.Context, admissionNamespace string, pod *corev1.Pod) (datapath.ClientConfig, error) {
	cfg := datapath.ClientConfig{}
	ns := admissionNamespace
	if ns == "" {
		ns = pod.Namespace
	}
	if ns == "" {
		return cfg, fmt.Errorf("pod namespace is required")
	}
	name := pod.Labels[GatewayLabel]
	gatewayNS := pod.Labels[GatewayNamespace]
	if annotation := pod.Annotations[GatewayNamespace]; annotation != "" {
		if gatewayNS != "" && gatewayNS != annotation {
			return cfg, fmt.Errorf("conflicting gateway namespace label and annotation")
		}
		gatewayNS = annotation
	}
	if gatewayNS == "" {
		gatewayNS = h.Namespace
	}
	if gatewayNS == "" {
		return cfg, fmt.Errorf("operator NAMESPACE is required to resolve gateway")
	}
	var gateway v1alpha1.EgressGateway
	if err := h.Client.Get(ctx, types.NamespacedName{Namespace: gatewayNS, Name: name}, &gateway); err != nil {
		return cfg, fmt.Errorf("resolve EgressGateway: %w", err)
	}
	if err := supportedGateway(&gateway); err != nil {
		return cfg, err
	}
	var namespace corev1.Namespace
	if err := h.Client.Get(ctx, types.NamespacedName{Name: ns}, &namespace); err != nil {
		return cfg, fmt.Errorf("resolve workload namespace: %w", err)
	}
	if gateway.Spec.AllowedNamespaces.NamespaceSelector == nil {
		return cfg, fmt.Errorf("gateway denies all namespaces: namespaceSelector is absent")
	}
	selector, err := metav1.LabelSelectorAsSelector(gateway.Spec.AllowedNamespaces.NamespaceSelector)
	if err != nil {
		return cfg, fmt.Errorf("invalid namespaceSelector: %w", err)
	}
	if !selector.Matches(labels.Set(namespace.Labels)) {
		return cfg, fmt.Errorf("namespace %s is not allowed by gateway", ns)
	}
	if gateway.Status.GatewayID == 0 || gateway.Status.GatewayID > 0xffffff {
		return cfg, fmt.Errorf("gatewayID not allocated; retry after gateway reconciliation")
	}
	matches, err := h.matchingPolicies(ctx, ns, pod.Labels)
	if err != nil {
		return cfg, err
	}
	if len(matches) > 1 {
		return cfg, fmt.Errorf("multiple EgressPolicies match pod: %s and %s", matches[0].Name, matches[1].Name)
	}
	encryption := gateway.Spec.Encryption
	if encryption == "" {
		encryption = "none"
	}
	cfg = datapath.ClientConfig{GatewayID: gateway.Status.GatewayID, AllowCloudMetadata: gateway.Spec.Exclusions.AllowCloudMetadata, MTU: 0, Encryption: encryption, Identity: datapath.Identity{Namespace: ns, Pod: pod.Name}, Exclusions: []netip.Prefix{}}
	if len(matches) == 1 {
		policy := matches[0]
		policyNS := policy.Spec.GatewayRef.Namespace
		if policyNS == "" {
			policyNS = h.Namespace
		}
		if policy.Spec.GatewayRef.Name != name || policyNS != gatewayNS {
			return cfg, fmt.Errorf("EgressPolicy %s gatewayRef %s/%s does not match selected gateway %s/%s", policy.Name, policyNS, policy.Spec.GatewayRef.Name, gatewayNS, name)
		}
		compiled, err := policycompiler.Compile(policy.Spec)
		if err != nil {
			return cfg, fmt.Errorf("compile EgressPolicy %s: %w", policy.Name, err)
		}
		cfg.Identity.Policy = policy.Name
		cfg.Policy = compiled
	}
	for _, e := range gateway.Status.EffectiveExclusions {
		prefix, err := netip.ParsePrefix(e.CIDR)
		if err != nil || !prefix.Addr().Is4() {
			return cfg, fmt.Errorf("gateway has invalid effective exclusion %q", e.CIDR)
		}
		cfg.Exclusions = append(cfg.Exclusions, prefix)
	}
	for _, endpoint := range gateway.Status.Endpoints {
		ip, err := netip.ParseAddr(endpoint.PodIP)
		if endpoint.UpstreamHealthy && err == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() {
			if encryption == "wireguard" {
				if err := validateWireGuardEndpoint(&endpoint); err != nil {
					return cfg, err
				}
				// Populate the selected endpoint's public key and registration CA
				// once the committed datapath ClientConfig fields are available.
				return cfg, fmt.Errorf("WireGuard client public-key, port and CA-pin datapath fields are not available yet")
			}
			cfg.Endpoint = ip
			break
		}
	}
	// An absent endpoint is intentional: the init backend installs an unreachable route.
	return cfg, nil
}

func supportedGateway(g *v1alpha1.EgressGateway) error {
	if g.Spec.Encryption != "" && g.Spec.Encryption != "none" && g.Spec.Encryption != "wireguard" {
		return fmt.Errorf("gateway encryption %q is unsupported", g.Spec.Encryption)
	}
	if g.Spec.DNS.Mode != "" && g.Spec.DNS.Mode != "cluster" && g.Spec.DNS.Mode != "gateway" {
		return fmt.Errorf("gateway DNS mode %q is unsupported", g.Spec.DNS.Mode)
	}
	if g.Spec.Upstream.Type != "openvpn" {
		return fmt.Errorf("gateway upstream %q is not implemented in M2", g.Spec.Upstream.Type)
	}
	if g.Spec.FailMode != "" && g.Spec.FailMode != "closed" {
		return fmt.Errorf("gateway failMode must be closed")
	}
	return nil
}
func (h *Handler) matchingPolicies(ctx context.Context, ns string, podLabels map[string]string) ([]v1alpha1.EgressPolicy, error) {
	var list v1alpha1.EgressPolicyList
	if err := h.Client.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("list EgressPolicies: %w", err)
	}
	var matches []v1alpha1.EgressPolicy
	for _, p := range list.Items {
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.WorkloadSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid selector on EgressPolicy %s: %w", p.Name, err)
		}
		if sel.Matches(labels.Set(podLabels)) {
			matches = append(matches, p)
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
		var pod corev1.Pod
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			return denied(err)
		}
		if req.Operation == admissionv1.Create {
			if pod.Labels[GatewayLabel] == "" {
				return admission.Allowed("not opted in")
			}
			if err := h.validateInjectedPod(ctx, req.Namespace, &pod); err != nil {
				return denied(fmt.Errorf("opted-in pod lacks safe Ratatoskr mutation: %w", err))
			}
			return admission.Allowed("client init injected")
		}
		var old corev1.Pod
		if err := json.Unmarshal(req.OldObject.Raw, &old); err != nil {
			return denied(err)
		}
		// Mutation only runs on CREATE. Changing gateway selection on any UPDATE,
		// including Pending pods, could start a workload without the injected init.
		if !sameMapEntry(old.Labels, pod.Labels, GatewayLabel) ||
			!sameMapEntry(old.Labels, pod.Labels, GatewayNamespace) ||
			!sameMapEntry(old.Annotations, pod.Annotations, GatewayNamespace) {
			return denied(fmt.Errorf("pod gateway opt-in and gateway namespace are immutable; change the Deployment template and recreate the pod"))
		}
		// A restarted init can read the annotation again. Do not allow a pod
		// creator to swap a validated policy, exclusion or remote after CREATE.
		if old.Labels[GatewayLabel] != "" && !sameMapEntry(old.Annotations, pod.Annotations, ConfigAnnotation) {
			return denied(fmt.Errorf("pod client config is immutable; recreate the pod to change its gateway configuration"))
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
		if _, err := policycompiler.Compile(policy.Spec); err != nil {
			return denied(fmt.Errorf("compile EgressPolicy %s: %w", policy.Name, err))
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
		// Reject overlapping selectors even when no selected Pod exists yet.
		var policies v1alpha1.EgressPolicyList
		if err := h.Client.List(ctx, &policies, client.InNamespace(ns)); err != nil {
			return denied(fmt.Errorf("list EgressPolicies: %w", err))
		}
		for _, other := range policies.Items {
			if other.Name == policy.Name {
				continue
			}
			overlap, err := selectorsOverlap(&policy.Spec.WorkloadSelector, &other.Spec.WorkloadSelector)
			if err != nil {
				return denied(err)
			}
			if overlap {
				return denied(fmt.Errorf("policy %s overlaps policy %s on a possible workload", policy.Name, other.Name))
			}
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
				if other.Name != policy.Name {
					return denied(fmt.Errorf("policy %s overlaps %s on pod %s", policy.Name, other.Name, p.Name))
				}
			}
		}
	default:
		return denied(fmt.Errorf("unexpected admission kind %q", req.Kind.Kind))
	}
	return admission.Allowed("valid")
}

// validateInjectedPod ensures that a selected pod cannot be admitted while the
// mutator is unavailable. The init must read the operator's annotation through
// the Downward API, rather than an arbitrary user-supplied command or file.
func (h *Handler) validateInjectedPod(ctx context.Context, admissionNamespace string, pod *corev1.Pod) error {
	if h.InitImage == "" || pod.Spec.HostNetwork || len(pod.Spec.InitContainers) == 0 {
		return fmt.Errorf("expected Ratatoskr init container is missing or unsupported")
	}
	init := pod.Spec.InitContainers[0]
	if init.Name != initName || init.Image != h.InitImage || len(init.Command) != 0 ||
		len(init.Args) != 1 || init.Args[0] != "-config=/var/run/ratatoskr/client.json" {
		return fmt.Errorf("expected Ratatoskr init image, entrypoint and config argument")
	}
	if init.SecurityContext == nil || init.SecurityContext.Privileged == nil || *init.SecurityContext.Privileged ||
		init.SecurityContext.Capabilities == nil || len(init.SecurityContext.Capabilities.Add) != 1 ||
		init.SecurityContext.Capabilities.Add[0] != "NET_ADMIN" || len(init.SecurityContext.Capabilities.Drop) != 0 {
		return fmt.Errorf("expected unprivileged Ratatoskr init with NET_ADMIN")
	}
	if len(init.VolumeMounts) < 1 || len(init.VolumeMounts) > 2 || init.VolumeMounts[0].Name != configVolume ||
		init.VolumeMounts[0].MountPath != "/var/run/ratatoskr" || !init.VolumeMounts[0].ReadOnly || init.VolumeMounts[0].SubPath != "" {
		return fmt.Errorf("expected read-only Ratatoskr config volume mount")
	}
	paths := map[string]string{"POD_IP": "status.podIP", "POD_UID": "metadata.uid", "POD_NAME": "metadata.name"}
	if len(init.Env) != len(paths) {
		return fmt.Errorf("expected Ratatoskr Downward API identity environment")
	}
	for _, env := range init.Env {
		path, ok := paths[env.Name]
		if !ok || env.Value != "" || env.ValueFrom == nil || env.ValueFrom.FieldRef == nil ||
			env.ValueFrom.FieldRef.FieldPath != path ||
			(env.ValueFrom.FieldRef.APIVersion != "" && env.ValueFrom.FieldRef.APIVersion != "v1") {
			return fmt.Errorf("expected Ratatoskr Downward API identity environment")
		}
		delete(paths, env.Name)
	}
	if len(paths) != 0 {
		return fmt.Errorf("duplicate Ratatoskr identity environment")
	}
	volumeFound := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name != configVolume {
			continue
		}
		if volumeFound || volume.DownwardAPI == nil || len(volume.DownwardAPI.Items) != 1 {
			return fmt.Errorf("expected unique Ratatoskr Downward API config volume")
		}
		item := volume.DownwardAPI.Items[0]
		if item.Path != "client.json" || item.FieldRef == nil ||
			item.FieldRef.FieldPath != "metadata.annotations['"+ConfigAnnotation+"']" ||
			(item.FieldRef.APIVersion != "" && item.FieldRef.APIVersion != "v1") {
			return fmt.Errorf("expected Ratatoskr annotation projection")
		}
		volumeFound = true
	}
	if !volumeFound {
		return fmt.Errorf("ratatoskr config volume missing")
	}
	if pod.Annotations[ReadyAnnotation] != "pending" {
		return fmt.Errorf("datapath readiness must remain pending until init succeeds")
	}
	config := pod.Annotations[ConfigAnnotation]
	if config == "" {
		return fmt.Errorf("operator-generated client config annotation missing")
	}
	var cfg datapath.ClientConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return fmt.Errorf("client config annotation invalid: %w", err)
	}
	expected, err := h.clientConfig(ctx, admissionNamespace, pod)
	if err != nil {
		return fmt.Errorf("resolve authorized client config: %w", err)
	}
	// Compare canonical JSON of typed configs: nil and empty slices that encode
	// identically are equivalent. A forged endpoint, gateway ID, exclusion,
	// metadata allowance, identity, encryption or policy still differs.
	actualJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode submitted client config: %w", err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("encode authorized client config: %w", err)
	}
	if !bytes.Equal(actualJSON, expectedJSON) {
		return fmt.Errorf("client config differs from authorized gateway status")
	}
	if expected.Encryption == "wireguard" {
		if err := validateWireGuardToken(pod); err != nil {
			return err
		}
	} else {
		if len(init.VolumeMounts) != 1 {
			return fmt.Errorf("unencrypted init must not mount WireGuard token")
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.Name == wgTokenVolume {
				return fmt.Errorf("unencrypted pod must not project WireGuard token")
			}
		}
	}
	return h.validateGatewayDNS(ctx, admissionNamespace, pod)
}

func sameMapEntry(old, updated map[string]string, key string) bool {
	oldValue, oldPresent := old[key]
	newValue, newPresent := updated[key]
	return oldPresent == newPresent && oldValue == newValue
}
