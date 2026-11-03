package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/observability"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// gatewayMetricsIngress parses only typed Kubernetes LabelSelectors. They are
// operator-configured chart values, never arbitrary kubectl selector strings.
func (r *GatewayReconciler) gatewayMetricsIngress() (*networkingv1.NetworkPolicyPeer, bool, error) {
	enabledValue := r.Options.GatewayMetricsEnabled
	if enabledValue == "" { // Direct controller test callers and pre-metrics releases.
		enabledValue = "false"
	}
	enabled, err := observability.MetricsEnabled(enabledValue)
	if err != nil {
		return nil, false, err
	}
	if !enabled {
		return nil, false, nil
	}
	decode := func(raw string) (*metav1.LabelSelector, error) {
		// An empty or {} selector admits every Pod in every namespace. Never
		// turn a missing controller env value into unauthenticated metrics
		// ingress, even if a chart normally supplies both selectors.
		if raw == "" {
			return nil, fmt.Errorf("configured metrics ingress selectors must be nonempty")
		}
		var selector metav1.LabelSelector
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&selector); err != nil || dec.Decode(new(any)) != io.EOF ||
			len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
			return nil, fmt.Errorf("invalid or empty configured metrics ingress selector")
		}
		if _, err := metav1.LabelSelectorAsSelector(&selector); err != nil {
			return nil, fmt.Errorf("invalid configured metrics ingress selector")
		}
		return &selector, nil
	}
	ns, err := decode(r.Options.GatewayMetricsNamespaceSelector)
	if err != nil {
		return nil, false, err
	}
	pod, err := decode(r.Options.GatewayMetricsPodSelector)
	if err != nil {
		return nil, false, err
	}
	return &networkingv1.NetworkPolicyPeer{NamespaceSelector: ns, PodSelector: pod}, true, nil
}

func ptrInt32(value int32) *int32                     { return &value }
func ptrPort(value int32) *intstr.IntOrString         { v := intstr.FromInt32(value); return &v }
func protocol(value corev1.Protocol) *corev1.Protocol { return &value }

// gatewayAPIVolume projects only public cluster trust roots and a rotating,
// short-lived gateway Pod-bound API token into the gateway container. The
// OpenVPN upstream container must never mount this volume.
func gatewayAPIVolume() corev1.Volume {
	lifetime := int64(3600)
	return corev1.Volume{Name: "gateway-api", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: ptrInt32(0444), Sources: []corev1.VolumeProjection{
		{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &lifetime}},
		{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
		{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}}}},
	}}}}
}

// upstreamProbeArgs is an operator-only override. Keep the default plugin
// probe untouched unless explicitly configured; only literal unicast IPv4
// endpoints are accepted to avoid leaking probe DNS or credentials. The plugin
// independently validates the URL and binds/marks the probe socket to upstream0.
func upstreamProbeArgs(endpoint string) ([]string, error) {
	if endpoint == "" {
		return nil, nil
	}
	if len(endpoint) > 2048 || strings.TrimSpace(endpoint) != endpoint {
		return nil, fmt.Errorf("invalid upstream probe URL")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream probe URL")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.String() != u.Hostname() {
		return nil, fmt.Errorf("upstream probe requires unicast IPv4 literal")
	}
	if port := u.Port(); port != "" {
		var n int
		if _, err := fmt.Sscanf(port, "%d", &n); err != nil || n < 1 || n > 65535 || fmt.Sprint(n) != port {
			return nil, fmt.Errorf("invalid upstream probe port")
		}
	}
	return []string{"--probe-url", endpoint}, nil
}

func (r *GatewayReconciler) render(gw *api.EgressGateway, ips []netip.Addr, clusterDNS ...string) ([]client.Object, error) {
	if _, err := gatewayProfileNames(gw); err != nil {
		return nil, err
	}
	metricsPeer, metricsEnabled, err := r.gatewayMetricsIngress()
	if err != nil {
		return nil, err
	}
	probeArgs, err := upstreamProbeArgs(r.Options.GatewayUpstreamProbeURL)
	if err != nil {
		return nil, err
	}
	if gw.Spec.Exclusions.AutoDetect != nil && !*gw.Spec.Exclusions.AutoDetect {
		return nil, fmt.Errorf("disabled automatic exclusions are not supported")
	}
	// No POD_IP or private key is serialized; the gateway obtains both inside its
	// own network namespace. The selected encryption mode preserves one GENEVE path.
	mode := gw.Spec.Encryption
	if mode == "" {
		mode = "none"
	}
	if mode == "wireguard" && gw.Namespace != r.Options.OperatorNamespace {
		return nil, fmt.Errorf("WireGuard gateway must live in operator namespace until scoped RBAC is configured")
	}
	config := datapath.GatewayConfig{GatewayID: gw.Status.GatewayID, Clients: ips, MTU: 1400, Encryption: mode}
	if config.Clients == nil {
		config.Clients = []netip.Addr{}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	selector := map[string]string{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID)}
	owner := []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: owner}, Data: map[string]string{"gateway.json": string(data)}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: owner}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: selector, Ports: []corev1.ServicePort{{Name: "geneve", Port: datapath.GenevePort, TargetPort: intstr.FromInt32(datapath.GenevePort), Protocol: corev1.ProtocolUDP}}}}
	replicas := gw.Spec.Replicas
	if replicas == 0 { // API-server default is 1; fake-client and upgrade paths may omit it.
		replicas = 1
	}
	if replicas < 1 || replicas > 32 {
		return nil, fmt.Errorf("gateway replicas must be in 1..32")
	}
	pull := corev1.PullIfNotPresent
	if r.Options.ImagePullPolicy != "" {
		pull = corev1.PullPolicy(r.Options.ImagePullPolicy)
	}
	priv := false
	root := int64(0)
	backendMode := r.Options.Datapath
	if backendMode == "" {
		backendMode = "iproute"
	}
	if backendMode != "iproute" && backendMode != "ebpf" {
		return nil, fmt.Errorf("unsupported datapath %q", backendMode)
	}
	if backendMode == "ebpf" && mode == "wireguard" {
		return nil, fmt.Errorf("ebpf datapath does not support WireGuard")
	}
	// Default /proc/sys is read-only under ordinary container isolation even
	// with NET_ADMIN. Only the gateway process needs privileged container access
	// to set forwarding in this Pod's network namespace; the upstream, agent and
	// selected workloads retain their separate security contexts. Do not claim
	// a capability-only bound for this container: privileged grants broad access.
	gatewayPrivileged := true
	pod := corev1.PodSpec{DNSPolicy: corev1.DNSClusterFirst, AutomountServiceAccountToken: &priv,
		Volumes: []corev1.Volume{
			{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: gw.Name}}}},
			{Name: "upstream", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: gw.Spec.Upstream.SecretRef.Name, DefaultMode: ptrInt32(0400)}}},
			{Name: "run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
			{Name: "dev-net", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		}, Containers: []corev1.Container{
			{Name: "gateway", Image: r.Options.GatewayImage, ImagePullPolicy: pull, Command: []string{"/ratatoskr", "-config", "/config/gateway.json"}, Env: []corev1.EnvVar{{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}}, {Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}, {Name: "DATAPATH", Value: backendMode}}, Ports: []corev1.ContainerPort{{Name: "geneve", ContainerPort: datapath.GenevePort, Protocol: corev1.ProtocolUDP}, {Name: "health", ContainerPort: 9900}}, VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/config", ReadOnly: true}}, SecurityContext: &corev1.SecurityContext{RunAsUser: &root, Privileged: &gatewayPrivileged}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(9900)}}, PeriodSeconds: 5}},
			{Name: "upstream", Image: r.Options.OpenVPNImage, ImagePullPolicy: pull, VolumeMounts: []corev1.VolumeMount{{Name: "upstream", MountPath: "/etc/ratatoskr/upstream", ReadOnly: true}, {Name: "run", MountPath: "/run/ratatoskr"}, {Name: "dev-net", MountPath: "/dev/net"}}, SecurityContext: &corev1.SecurityContext{RunAsUser: &root, AllowPrivilegeEscalation: &priv, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "MKNOD"}, Drop: []corev1.Capability{"ALL"}}}},
		}}
	if metricsEnabled {
		pod.Containers[0].Env = append(pod.Containers[0].Env,
			corev1.EnvVar{Name: "METRICS_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "METRICS_BIND_ADDRESS", Value: "0.0.0.0:9902"})
		pod.Containers[0].Ports = append(pod.Containers[0].Ports,
			corev1.ContainerPort{Name: "metrics", ContainerPort: 9902, Protocol: corev1.ProtocolTCP})
	} else if r.Options.GatewayMetricsEnabled != "" {
		pod.Containers[0].Env = append(pod.Containers[0].Env, corev1.EnvVar{Name: "METRICS_ENABLED", Value: "false"})
	}
	// The upstream plugin retains its own default probe unless the operator
	// explicitly selects a private endpoint (never configurable by a workload).
	pod.Containers[1].Args = probeArgs
	if mode == "wireguard" {
		pod.ServiceAccountName = "ratatoskr-gateway"
		pod.Volumes = append(pod.Volumes, gatewayAPIVolume())
		gateway := &pod.Containers[0]
		gateway.VolumeMounts = append(gateway.VolumeMounts, corev1.VolumeMount{Name: "gateway-api", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true})
		gateway.Env = append(gateway.Env,
			corev1.EnvVar{Name: "GATEWAY_NAME", Value: gw.Name},
			corev1.EnvVar{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
			corev1.EnvVar{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		)
		gateway.Ports = append(gateway.Ports, corev1.ContainerPort{Name: "wg-transport", ContainerPort: int32(datapath.WireGuardPortDefault), Protocol: corev1.ProtocolUDP}, corev1.ContainerPort{Name: "registration", ContainerPort: 9443, Protocol: corev1.ProtocolTCP})
	}
	for k, v := range gw.Spec.NodeSelector {
		if pod.NodeSelector == nil {
			pod.NodeSelector = map[string]string{}
		}
		pod.NodeSelector[k] = v
	}
	for _, t := range gw.Spec.Tolerations {
		tol := corev1.Toleration{Key: t.Key, Operator: corev1.TolerationOperator(t.Operator), Value: t.Value, Effect: corev1.TaintEffect(t.Effect), TolerationSeconds: t.TolerationSeconds}
		pod.Tolerations = append(pod.Tolerations, tol)
	}
	c := &pod.Containers[0]
	c.Resources = corev1.ResourceRequirements{Limits: corev1.ResourceList{}, Requests: corev1.ResourceList{}}
	for k, v := range gw.Spec.Resources.Gateway.Limits {
		c.Resources.Limits[corev1.ResourceName(k)] = resource.MustParse(v.String())
	}
	for k, v := range gw.Spec.Resources.Gateway.Requests {
		c.Resources.Requests[corev1.ResourceName(k)] = resource.MustParse(v.String())
	}
	if gw.Spec.DNS.Mode == "gateway" {
		if len(clusterDNS) == 0 || clusterDNS[0] == "" {
			return nil, fmt.Errorf("cluster DNS IPv4 unavailable")
		}
		var clusterCIDRs []string
		hasPod, hasService := false, false
		for _, exclusion := range gw.Status.EffectiveExclusions {
			switch exclusion.Source {
			case "podCIDR":
				hasPod = true
				clusterCIDRs = append(clusterCIDRs, exclusion.CIDR)
			case "serviceCIDR":
				hasService = true
				clusterCIDRs = append(clusterCIDRs, exclusion.CIDR)
			}
		}
		if !hasPod || !hasService {
			return nil, fmt.Errorf("cluster Pod and Service CIDRs required for safe DNS reverse forwarding")
		}
		upstreamDNS := r.Options.GatewayUpstreamDNSIP
		if upstreamDNS != "" {
			ip, err := netip.ParseAddr(upstreamDNS)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
				return nil, fmt.Errorf("invalid GATEWAY_UPSTREAM_DNS_IP")
			}
		}
		domain := r.Options.ClusterDomain
		if domain == "" {
			domain = "cluster.local"
		}
		pod.Containers[0].Env = append(pod.Containers[0].Env, corev1.EnvVar{Name: "CLUSTER_DNS_IP", Value: clusterDNS[0]}, corev1.EnvVar{Name: "CLUSTER_DOMAIN", Value: domain}, corev1.EnvVar{Name: "GATEWAY_DNS_LISTEN_ADDR", Value: ":1053"}, corev1.EnvVar{Name: "CLUSTER_CIDRS", Value: strings.Join(clusterCIDRs, ",")})
		if upstreamDNS != "" {
			pod.Containers[0].Env = append(pod.Containers[0].Env, corev1.EnvVar{Name: "UPSTREAM_DNS_IP", Value: upstreamDNS})
		}
		pod.Containers[0].Ports = append(pod.Containers[0].Ports, corev1.ContainerPort{Name: "dns-udp", ContainerPort: 1053, Protocol: corev1.ProtocolUDP}, corev1.ContainerPort{Name: "dns-tcp", ContainerPort: 1053, Protocol: corev1.ProtocolTCP})
	}
	objects := []client.Object{cm, svc}
	if len(gw.Spec.Upstream.Profiles) == 0 {
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, Labels: selector, OwnerReferences: owner}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}, Selector: &metav1.LabelSelector{MatchLabels: selector}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: selector}, Spec: pod}}}
		objects = append(objects, dep)
	} else {
		for _, profile := range gw.Spec.Upstream.Profiles {
			profilePod := *pod.DeepCopy()
			profilePod.Volumes[1].Secret.SecretName = profile.SecretRef.Name
			identity := map[string]string{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID), profileLabel: profile.Name}
			one := int32(1)
			dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: profileDeploymentName(gw.Name, profile.Name), Namespace: gw.Namespace, Labels: identity, OwnerReferences: owner}, Spec: appsv1.DeploymentSpec{Replicas: &one, Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}, Selector: &metav1.LabelSelector{MatchLabels: identity}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: identity}, Spec: profilePod}}}
			objects = append(objects, dep)
		}
	}
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: owner}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: selector}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}}
	// Kubelet readiness and controller /info use PodIP from host/network locations
	// not expressible as portable namespace/pod selectors; keep only this TCP port open.
	np.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocol(corev1.ProtocolTCP), Port: ptrPort(9900)}}}}
	if gw.Spec.AllowedNamespaces.NamespaceSelector != nil {
		peers := []networkingv1.NetworkPolicyPeer{{NamespaceSelector: gw.Spec.AllowedNamespaces.NamespaceSelector.DeepCopy(), PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{GatewayLabel: gw.Name}}}}
		if mode == "wireguard" {
			// WireGuard UDP packets originate from selected workload PodIPs, so
			// retain the exact namespace+Pod selector on transport ingress.
			np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: peers, Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocol(corev1.ProtocolUDP), Port: ptrPort(int32(datapath.WireGuardPortDefault))}}})
			// The authenticated node agent uses hostNetwork: its node-source IP
			// cannot be matched portably by a Pod/Namespace selector. Reachability
			// on TCP9443 is intentionally broader than authorization: TLS 1.3
			// pins the gateway PodIP/CA and the server requires a current Pod-UID-
			// bound audience token, TokenReview and selected Pod identity. Never
			// broaden UDP51820 or admit plaintext UDP6081 for encrypted mode.
			np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocol(corev1.ProtocolTCP), Port: ptrPort(9443)}}})
		} else {
			np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: peers, Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocol(corev1.ProtocolUDP), Port: ptrPort(datapath.GenevePort)}}})
		}
		if gw.Spec.DNS.Mode == "gateway" {
			np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: peers, Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocol(corev1.ProtocolUDP), Port: ptrPort(1053)}, {Protocol: protocol(corev1.ProtocolTCP), Port: ptrPort(1053)}}})
		}
	}

	if metricsEnabled {
		metrics := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-metrics", Namespace: gw.Namespace, Labels: selector, OwnerReferences: owner}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: selector, Ports: []corev1.ServicePort{{Name: "metrics", Port: 9902, TargetPort: intstr.FromInt32(9902), Protocol: corev1.ProtocolTCP}}}}
		objects = append(objects, metrics)
		np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: []networkingv1.NetworkPolicyPeer{*metricsPeer}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocol(corev1.ProtocolTCP), Port: ptrPort(9902)}}})
	}
	if gw.Spec.DNS.Mode == "gateway" {
		dns := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-dns", Namespace: gw.Namespace, OwnerReferences: owner}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, PublishNotReadyAddresses: true, Selector: selector, Ports: []corev1.ServicePort{{Name: "dns-udp", Port: 53, TargetPort: intstr.FromInt32(1053), Protocol: corev1.ProtocolUDP}, {Name: "dns-tcp", Port: 53, TargetPort: intstr.FromInt32(1053), Protocol: corev1.ProtocolTCP}}}}
		objects = append(objects, dns)
	}
	return append(objects, np), nil
}
