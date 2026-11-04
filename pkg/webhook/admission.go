// Package webhook implements fail-closed Ratatoskr admission and TLS bootstrap.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlLog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/datapath/affinity"
	policycompiler "github.com/skaldhall/ratatoskr/pkg/policy"
)

const (
	prefix               = "ratatoskr.skaldhall.io/"
	GatewayLabel         = prefix + "gateway"
	GatewayNamespace     = prefix + "gateway-namespace"
	ConfigAnnotation     = prefix + "client-config"
	ReadyAnnotation      = prefix + "datapath-ready"
	appliedAckAnnotation = prefix + "gateway-applied-ack"
	initName             = "ratatoskr-init"
	configVolume         = "ratatoskr-client-config"
	wgTokenVolume        = "ratatoskr-wg-token"             // #nosec G101 -- volume name, not a token value.
	wgTokenAudience      = "ratatoskr.skaldhall.io/gateway" // #nosec G101 -- projected token audience, not a credential.
	wgTokenMount         = "/var/run/ratatoskr/wg-token"    // #nosec G101 -- fixed mount path, not token bytes.
)

// API-generated Pod names use an opaque five-character suffix. A prefix alone
// is insufficient to identify admission-time generated intent securely.
var generatedSuffix = regexp.MustCompile(`^[a-z0-9]{5}$`)

type Handler struct {
	Client                              client.Client
	Namespace, InitImage, ClusterDomain string
	// AgentNamespace is the node-agent ServiceAccount namespace, not necessarily
	// the default gateway namespace for standalone webhook deployments.
	AgentNamespace   string
	Driver, Datapath string
	// Optional test-injected logger; production uses controller-runtime's JSON
	// logger configured by cmd/webhook. No object or raw denial body is logged.
	Logger logr.Logger
}

func (h *Handler) driver() string {
	if h.Driver == "" {
		return "init"
	}
	return h.Driver
}

func (h *Handler) datapath() string {
	if h.Datapath == "" {
		return "iproute"
	}
	return h.Datapath
}

func (h *Handler) initCapabilities() []corev1.Capability {
	if h.datapath() == "ebpf" {
		return []corev1.Capability{"NET_ADMIN", "BPF", "PERFMON"}
	}
	return []corev1.Capability{"NET_ADMIN"}
}

func (h *Handler) validateModes() error {
	if h.driver() != "init" && h.driver() != "agent" {
		return fmt.Errorf("unsupported DRIVER %q", h.Driver)
	}
	if h.Datapath != "" && h.Datapath != "iproute" && h.Datapath != "ebpf" {
		return fmt.Errorf("unsupported DATAPATH %q", h.Datapath)
	}
	return nil
}

func denied(err error) admission.Response { return admission.Denied(err.Error()) }

// admissionCategory is deliberately fixed and bounded: never log an error
// message, submitted object, annotation, identity value, Secret or token.
func admissionCategory(result admission.Response) string {
	if result.Allowed {
		return "allowed"
	}
	if result.Result == nil {
		return "denied-other"
	}
	message := result.Result.Message
	for _, category := range []string{"identity-pod", "identity-namespace", "identity-uid",
		"identity-policy", "gateway-id", "encryption", "gateway-endpoint-identity",
		"gateway-status", "authorized-policy", "config-rollout"} {
		if strings.HasSuffix(message, "client config differs from authorized gateway status ("+category+")") {
			return category
		}
	}
	return "denied-other"
}

func (h *Handler) auditAdmission(ctx context.Context, req admission.Request, stage string, response admission.Response) {
	logger := h.Logger
	if logger.GetSink() == nil {
		logger = ctrlLog.FromContext(ctx)
	}
	// Admission UID is an API-generated correlation ID; never log Pod name,
	// namespace value, raw response/error or user-controlled labels.
	logger.Info("ratatoskr admission decision", "stage", stage, "operation", string(req.Operation),
		"kind", req.Kind.Kind, "requestUID", string(req.UID), "driver", h.driver(),
		"allowed", response.Allowed, "category", admissionCategory(response))
}

// gatewaySelection makes annotation opt-in visible to the existing label-based
// controller/network-policy datapath. Only CREATE mutation may add the label;
// conflicting representations and malformed names always fail closed.
func gatewaySelection(pod *corev1.Pod) (string, error) {
	label, annotation := pod.Labels[GatewayLabel], pod.Annotations[GatewayLabel]
	if label != "" && annotation != "" && label != annotation {
		return "", fmt.Errorf("gateway label and annotation conflict")
	}
	value := label
	if value == "" {
		value = annotation
	}
	if value != "" && !validSecretName(value) {
		return "", fmt.Errorf("gateway selection name is invalid")
	}
	return value, nil
}

func (h *Handler) MutatePod(ctx context.Context, req admission.Request) (response admission.Response) {
	defer func() { h.auditAdmission(ctx, req, "mutate", response) }()
	if req.Operation != admissionv1.Create {
		return admission.Allowed("not a pod create")
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denied(err)
	}
	name, err := gatewaySelection(&pod)
	if err != nil {
		return denied(err)
	}
	if name == "" {
		return admission.Allowed("not opted in")
	}
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[GatewayLabel] = name
	if err := h.validateModes(); err != nil {
		return denied(err)
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
		if v.Name == configVolume || v.Name == wgTokenVolume || v.Name == agentShadowVolume {
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
	if h.driver() == "agent" {
		for _, c := range append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...) {
			for _, mount := range c.VolumeMounts {
				if mount.Name == agentShadowVolume {
					return denied(fmt.Errorf("reserved agent API-token shadow mount already exists"))
				}
			}
		}
		for _, c := range pod.Spec.EphemeralContainers {
			for _, mount := range c.VolumeMounts {
				if mount.Name == agentShadowVolume {
					return denied(fmt.Errorf("reserved agent API-token shadow mount already exists"))
				}
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
	if h.driver() == "init" {
		pod.Annotations[appliedAckAnnotation] = ""
	}
	if h.driver() == "agent" {
		// The node agent programs the pod netns and installs rtk-ready last. This
		// init only waits; it needs no API token, NET_ADMIN or config mount.
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: agentShadowVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		pod.Spec.InitContainers = append([]corev1.Container{agentWaitInit(h.InitImage)}, pod.Spec.InitContainers...)
	} else {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: configVolume, VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{{Path: "client.json", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.annotations['" + ConfigAnnotation + "']"}}, {Path: "applied-ack.json", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.annotations['" + appliedAckAnnotation + "']"}}}}}})
		privileged, nonRoot, root := false, false, int64(0)
		pod.Spec.InitContainers = append([]corev1.Container{{Name: initName, Image: h.InitImage, Args: []string{"-config=/var/run/ratatoskr/client.json"}, SecurityContext: &corev1.SecurityContext{
			RunAsUser: &root, RunAsNonRoot: &nonRoot, Privileged: &privileged, AllowPrivilegeEscalation: &privileged,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: h.initCapabilities()},
		}, Env: []corev1.EnvVar{
			{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
			{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
			{Name: "DATAPATH", Value: h.datapath()},
		}, VolumeMounts: []corev1.VolumeMount{{Name: configVolume, MountPath: "/var/run/ratatoskr", ReadOnly: true}}}}, pod.Spec.InitContainers...)
		if cfg.Encryption == "wireguard" {
			injectWireGuardToken(&pod)
		}
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
	if policyUsesDomains(matches) {
		if h.driver() != "agent" || gateway.Spec.DNS.Mode != "gateway" {
			return cfg, fmt.Errorf("domain selectors require driver=agent and gateway dns.mode=gateway")
		}
	}
	if h.driver() == "agent" {
		// The API server may assign generateName after mutation and before
		// validation. Preserve empty-name admission intent across both passes;
		// the agent resolves the assigned name and UID from the live Pod.
		// A supplied name must match its prefix; never normalize an unrelated
		// explicit identity. UID may already be assigned by CREATE validation,
		// but only the node agent can bind the actual Pod UID/name after scheduling.
		if pod.GenerateName != "" &&
			(pod.Name == "" || (strings.HasPrefix(pod.Name, pod.GenerateName) &&
				generatedSuffix.MatchString(strings.TrimPrefix(pod.Name, pod.GenerateName)))) {
			cfg.Identity.Pod = ""
		}
		// CREATE admission has no assigned Pod UID or post-CNI IP, and Gateway
		// endpoint/MTU/exclusion status can change between mutation and validation.
		// Persist only authorized immutable intent. The node agent resolves live
		// exclusions, endpoint identity and MTU after scheduling, before traffic.
		return cfg, nil
	}
	for _, e := range gateway.Status.EffectiveExclusions {
		prefix, err := netip.ParsePrefix(e.CIDR)
		if err != nil || !prefix.Addr().Is4() {
			return cfg, fmt.Errorf("gateway has invalid effective exclusion %q", e.CIDR)
		}
		cfg.Exclusions = append(cfg.Exclusions, prefix)
	}
	// UID is normally not assigned when Pod CREATE admission runs. An explicit
	// name is stable across both admission passes; a generateName prefix is not:
	// the API server can assign a different suffix after admission. The init
	// driver has no post-CNI opportunity to replace its fixed PodIP endpoint.
	key := string(pod.UID)
	if key == "" {
		if pod.Name == "" {
			if pod.GenerateName != "" && h.driver() == "agent" {
				// The agent will recompile with the assigned UID after scheduling;
				// do not publish an unauthenticated placeholder endpoint/CA.
				return cfg, nil
			}
			if pod.GenerateName != "" {
				return cfg, fmt.Errorf("generateName pod has no assigned name or UID at CREATE admission; init driver cannot stably select a gateway endpoint; use a named Pod or agent driver")
			}
			return cfg, fmt.Errorf("pod name or UID is required for stable gateway affinity")
		}
		key = ns + "/" + pod.Name
	}
	healthy := make(map[netip.Addr]v1alpha1.GatewayEndpoint)
	for _, endpoint := range gateway.Status.Endpoints {
		if !endpoint.UpstreamHealthy {
			continue
		}
		ip, err := netip.ParseAddr(endpoint.PodIP)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return cfg, fmt.Errorf("healthy gateway endpoint has invalid PodIP")
		}
		if prior, exists := healthy[ip]; exists && encryption == "wireguard" && (prior.WireguardPublicKey != endpoint.WireguardPublicKey || prior.RegistrationCACert != endpoint.RegistrationCACert) {
			return cfg, fmt.Errorf("duplicate gateway PodIP has conflicting WireGuard identity")
		}
		healthy[ip] = endpoint
	}
	if len(healthy) != 0 {
		ips := make([]netip.Addr, 0, len(healthy))
		for ip := range healthy {
			ips = append(ips, ip)
		}
		selected, err := affinity.Select(key, ips)
		if err != nil {
			return cfg, fmt.Errorf("select healthy gateway endpoint: %w", err)
		}
		cfg.Endpoint = selected
		if encryption == "wireguard" {
			endpoint := healthy[selected]
			if err := validateWireGuardEndpoint(&endpoint); err != nil {
				return cfg, err
			}
			// Key and CA always belong to this exact selected PodIP.
			cfg.GatewayPublicKey = endpoint.WireguardPublicKey
			cfg.RegistrationCACert = endpoint.RegistrationCACert
			cfg.WireGuardPort = datapath.WireGuardPortDefault
		}
	}
	// An absent endpoint is intentional: the init backend installs an unreachable route.
	return cfg, nil
}

// validProfileLabel is deliberately tighter than a generic Pod name: each
// profile is an immutable named controller child, never an arbitrary filename.
func validProfileLabel(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func validSecretName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 ||
		(label[0] < 'a' || label[0] > 'z') && (label[0] < '0' || label[0] > '9') ||
		(label[len(label)-1] < 'a' || label[len(label)-1] > 'z') && (label[len(label)-1] < '0' || label[len(label)-1] > '9') {
		return false
	}
	for _, char := range label {
		if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// Profiles cannot silently broaden a legacy single upstream into multiple
// exits. All referenced Secrets are names only within this Gateway namespace.
func validateUpstreamProfiles(g *v1alpha1.EgressGateway) error {
	upstream := g.Spec.Upstream
	if len(upstream.Profiles) == 0 {
		// Preserve legacy gateway admission: the controller reports an absent
		// upstream Secret as NotReady/SecretUnavailable. Do not let profiles
		// permit malformed explicitly named Secrets.
		if upstream.SecretRef.Name != "" && !validSecretName(upstream.SecretRef.Name) {
			return fmt.Errorf("legacy upstream Secret name is invalid")
		}
		return nil
	}
	if upstream.Type != "openvpn" || upstream.Image != "" || upstream.SecretRef.Name != "" ||
		len(upstream.Profiles) > 8 || g.Spec.Replicas > 1 {
		return fmt.Errorf("upstream profiles require openvpn, no legacy Secret/image and one replica")
	}
	seen := make(map[string]bool, len(upstream.Profiles))
	for _, profile := range upstream.Profiles {
		if !validProfileLabel(profile.Name) || seen[profile.Name] || !validSecretName(profile.SecretRef.Name) {
			return fmt.Errorf("upstream profile name or Secret reference invalid or duplicated")
		}
		seen[profile.Name] = true
	}
	return nil
}

func policyUsesDomains(policies []v1alpha1.EgressPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Spec.Rules {
			if len(rule.Domains) != 0 {
				return true
			}
		}
	}
	return false
}

func supportedGateway(g *v1alpha1.EgressGateway) error {
	if g.Spec.Encryption != "" && g.Spec.Encryption != "none" && g.Spec.Encryption != "wireguard" {
		return fmt.Errorf("gateway encryption %q is unsupported", g.Spec.Encryption)
	}
	if g.Spec.DNS.Mode != "" && g.Spec.DNS.Mode != "cluster" && g.Spec.DNS.Mode != "gateway" {
		return fmt.Errorf("gateway DNS mode %q is unsupported", g.Spec.DNS.Mode)
	}
	if g.Spec.Upstream.Type != "openvpn" {
		return fmt.Errorf("gateway upstream %q is not implemented; only openvpn is currently available", g.Spec.Upstream.Type)
	}
	if err := validateUpstreamProfiles(g); err != nil {
		return err
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
func (h *Handler) Validate(ctx context.Context, req admission.Request) (response admission.Response) {
	defer func() { h.auditAdmission(ctx, req, "validate", response) }()
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
			selected, err := gatewaySelection(&pod)
			if err != nil {
				return denied(err)
			}
			if selected == "" {
				return admission.Allowed("not opted in")
			}
			if pod.Labels[GatewayLabel] != selected {
				return denied(fmt.Errorf("gateway annotation requires mutated gateway label on CREATE"))
			}
			for _, key := range []string{prefix + "agent-config", prefix + "agent-hash", prefix + "agent-backend", prefix + "quarantine-reason"} {
				if _, supplied := pod.Annotations[key]; supplied {
					return denied(fmt.Errorf("agent-owned Pod state may not be supplied on CREATE"))
				}
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
			!sameMapEntry(old.Annotations, pod.Annotations, GatewayLabel) ||
			!sameMapEntry(old.Labels, pod.Labels, GatewayNamespace) ||
			!sameMapEntry(old.Annotations, pod.Annotations, GatewayNamespace) {
			return denied(fmt.Errorf("pod gateway opt-in and gateway namespace are immutable; change the Deployment template and recreate the pod"))
		}
		// Agent state hashes are checksums, not authentication. Only the
		// authenticated agent ServiceAccount may change its Pod state.
		if h.driver() == "agent" && old.Labels[GatewayLabel] != "" {
			for _, key := range []string{prefix + "agent-config", prefix + "agent-hash", prefix + "agent-backend", prefix + "quarantine-reason", ReadyAnnotation} {
				if !sameMapEntry(old.Annotations, pod.Annotations, key) &&
					(h.agentNamespace() == "" || req.UserInfo.Username != "system:serviceaccount:"+h.agentNamespace()+":ratatoskr-agent") {
					return denied(fmt.Errorf("only the node agent may update agent-owned Pod state"))
				}
			}
		}
		if h.driver() == "init" && old.Labels[GatewayLabel] != "" && !sameMapEntry(old.Annotations, pod.Annotations, appliedAckAnnotation) &&
			(h.agentNamespace() == "" || req.UserInfo.Username != "system:serviceaccount:"+h.agentNamespace()+":ratatoskr-controller") {
			return denied(fmt.Errorf("only the operator controller may update init applied gateway acknowledgement"))
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
		if policyUsesDomains([]v1alpha1.EgressPolicy{policy}) {
			if h.driver() != "agent" {
				return denied(fmt.Errorf("domain selectors require driver=agent"))
			}
			gatewayNS := policy.Spec.GatewayRef.Namespace
			if gatewayNS == "" {
				gatewayNS = h.Namespace
			}
			var gateway v1alpha1.EgressGateway
			if err := h.Client.Get(ctx, types.NamespacedName{Namespace: gatewayNS, Name: policy.Spec.GatewayRef.Name}, &gateway); err != nil {
				return denied(fmt.Errorf("domain selectors require an existing gateway with dns.mode=gateway"))
			}
			if gateway.Spec.DNS.Mode != "gateway" {
				return denied(fmt.Errorf("domain selectors require gateway dns.mode=gateway"))
			}
			if err := supportedGateway(&gateway); err != nil {
				return denied(err)
			}
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
	if err := h.validateModes(); err != nil {
		return err
	}
	init := pod.Spec.InitContainers[0]
	if h.driver() == "agent" {
		if err := validateAgentWaitInit(pod, h.InitImage); err != nil {
			return err
		}
	} else if init.Name != initName || init.Image != h.InitImage || len(init.Command) != 0 ||
		len(init.Args) != 1 || init.Args[0] != "-config=/var/run/ratatoskr/client.json" {
		return fmt.Errorf("expected Ratatoskr init image, entrypoint and config argument")
	}
	if h.driver() == "init" {
		sec := init.SecurityContext
		if sec == nil || sec.RunAsUser == nil || *sec.RunAsUser != 0 || sec.RunAsNonRoot == nil || *sec.RunAsNonRoot ||
			sec.Privileged == nil || *sec.Privileged || sec.AllowPrivilegeEscalation == nil || *sec.AllowPrivilegeEscalation ||
			sec.SeccompProfile == nil || sec.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault || sec.SeccompProfile.LocalhostProfile != nil ||
			sec.Capabilities == nil || !slices.Equal(sec.Capabilities.Add, h.initCapabilities()) ||
			!slices.Equal(sec.Capabilities.Drop, []corev1.Capability{"ALL"}) {
			return fmt.Errorf("expected root-UID-only Ratatoskr programming init with exact NET_ADMIN capabilities and RuntimeDefault")
		}
		if len(init.VolumeMounts) < 1 || len(init.VolumeMounts) > 2 || init.VolumeMounts[0].Name != configVolume ||
			init.VolumeMounts[0].MountPath != "/var/run/ratatoskr" || !init.VolumeMounts[0].ReadOnly || init.VolumeMounts[0].SubPath != "" {
			return fmt.Errorf("expected read-only Ratatoskr config volume mount")
		}
		paths := map[string]string{"POD_IP": "status.podIP", "POD_UID": "metadata.uid", "POD_NAME": "metadata.name"}
		if len(init.Env) != len(paths)+1 {
			return fmt.Errorf("expected Ratatoskr Downward API identity environment and DATAPATH")
		}
		datapathEnv := false
		for _, env := range init.Env {
			if env.Name == "DATAPATH" {
				if datapathEnv || env.Value != h.datapath() || env.ValueFrom != nil {
					return fmt.Errorf("programming init DATAPATH does not match webhook configuration")
				}
				datapathEnv = true
				continue
			}
			path, ok := paths[env.Name]
			if !ok || env.Value != "" || env.ValueFrom == nil || env.ValueFrom.FieldRef == nil ||
				env.ValueFrom.FieldRef.FieldPath != path ||
				(env.ValueFrom.FieldRef.APIVersion != "" && env.ValueFrom.FieldRef.APIVersion != "v1") {
				return fmt.Errorf("expected Ratatoskr Downward API identity environment")
			}
			delete(paths, env.Name)
		}
		if len(paths) != 0 || !datapathEnv {
			return fmt.Errorf("missing or duplicate Ratatoskr identity environment or DATAPATH")
		}
		volumeFound := false
		for _, volume := range pod.Spec.Volumes {
			if volume.Name != configVolume {
				continue
			}
			if volumeFound || volume.DownwardAPI == nil || len(volume.DownwardAPI.Items) != 2 {
				return fmt.Errorf("expected unique Ratatoskr config and applied-ack Downward API volume")
			}
			for i, item := range volume.DownwardAPI.Items {
				path, field := "client.json", "metadata.annotations['"+ConfigAnnotation+"']"
				if i == 1 {
					path, field = "applied-ack.json", "metadata.annotations['"+appliedAckAnnotation+"']"
				}
				if item.Path != path || item.FieldRef == nil || item.FieldRef.FieldPath != field ||
					(item.FieldRef.APIVersion != "" && item.FieldRef.APIVersion != "v1") {
					return fmt.Errorf("expected immutable Ratatoskr config and applied-ack annotation projection")
				}
			}
			volumeFound = true
		}
		if !volumeFound {
			return fmt.Errorf("ratatoskr config volume missing")
		}
	} else {
		// The agent reads the annotation from the API. It must never receive a
		// workload-mounted config file, privileged hostPath or gateway token.
		for _, volume := range pod.Spec.Volumes {
			if volume.Name == configVolume || volume.Name == wgTokenVolume {
				return fmt.Errorf("agent driver must not project Ratatoskr config or gateway token")
			}
		}
	}
	if h.driver() == "init" && pod.Annotations[appliedAckAnnotation] != "" {
		return fmt.Errorf("init applied gateway acknowledgement must begin pending")
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
		return fmt.Errorf("client config annotation invalid")
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
		return fmt.Errorf("client config differs from authorized gateway status (%s)", clientConfigMismatch(&cfg, &expected))
	}
	if h.driver() == "init" && expected.Encryption == "wireguard" {
		if err := validateWireGuardToken(pod); err != nil {
			return err
		}
	} else {
		if h.driver() == "init" && len(init.VolumeMounts) != 1 {
			return fmt.Errorf("unencrypted init must not mount WireGuard token")
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.Name == wgTokenVolume {
				return fmt.Errorf("agent or unencrypted pod must not project WireGuard token")
			}
		}
	}
	return h.validateGatewayDNS(ctx, admissionNamespace, pod)
}

// clientConfigMismatch emits only authored field categories, never Pod names,
// addresses, policy values, public CA material or token-bearing annotations.
// A mismatch still always denies; this only makes rollout diagnostics useful.
func clientConfigMismatch(actual, expected *datapath.ClientConfig) string {
	switch {
	case actual.Identity.Namespace != expected.Identity.Namespace:
		return "identity-namespace"
	case actual.Identity.Pod != expected.Identity.Pod:
		return "identity-pod"
	case actual.Identity.UID != expected.Identity.UID:
		return "identity-uid"
	case actual.Identity.Policy != expected.Identity.Policy:
		return "identity-policy"
	case actual.GatewayID != expected.GatewayID:
		return "gateway-id"
	case actual.Encryption != expected.Encryption:
		return "encryption"
	case actual.Endpoint != expected.Endpoint || actual.GatewayPublicKey != expected.GatewayPublicKey ||
		actual.RegistrationCACert != expected.RegistrationCACert || actual.WireGuardPort != expected.WireGuardPort:
		return "gateway-endpoint-identity"
	case actual.MTU != expected.MTU || !slices.Equal(actual.Exclusions, expected.Exclusions):
		return "gateway-status"
	case actual.AllowCloudMetadata != expected.AllowCloudMetadata || !reflect.DeepEqual(actual.Policy, expected.Policy):
		return "authorized-policy"
	default:
		return "config-rollout"
	}
}

func sameMapEntry(old, updated map[string]string, key string) bool {
	oldValue, oldPresent := old[key]
	newValue, newPresent := updated[key]
	return oldPresent == newPresent && oldValue == newValue
}
