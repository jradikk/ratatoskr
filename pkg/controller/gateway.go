// Package controller renders and reconciles the fail-closed gateway workload.
package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"time"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	GatewayLabel             = "ratatoskr.skaldhall.io/gateway"
	GatewayNamespace         = "ratatoskr.skaldhall.io/gateway-namespace"
	IdentityLabel            = "ratatoskr.skaldhall.io/gateway-name"
	ownerUIDLabel            = "ratatoskr.skaldhall.io/gateway-uid"
	datapathReadyAnnotation  = "ratatoskr.skaldhall.io/datapath-ready"
	clientInitContainer      = "ratatoskr-init"
	registrationCAAnnotation = "ratatoskr.skaldhall.io/registration-ca"
	wireguardKeyAnnotation   = "ratatoskr.skaldhall.io/wireguard-public-key"
)

type Options struct {
	OperatorNamespace, GatewayImage, OpenVPNImage, ImagePullPolicy, Driver, Datapath, ClusterDomain, ServiceCIDRs, PodCIDRs, ExtraCIDRs, GatewayUpstreamDNSIP, GatewayUpstreamProbeURL string
}

func OptionsFromEnv() Options {
	return Options{
		OperatorNamespace: os.Getenv("OPERATOR_NAMESPACE"), GatewayImage: os.Getenv("GATEWAY_IMAGE"), OpenVPNImage: os.Getenv("OPENVPN_IMAGE"), ImagePullPolicy: os.Getenv("IMAGE_PULL_POLICY"), Driver: os.Getenv("DRIVER"), Datapath: os.Getenv("DATAPATH"), ClusterDomain: os.Getenv("CLUSTER_DOMAIN"), ServiceCIDRs: os.Getenv("SERVICE_CIDRS"), PodCIDRs: os.Getenv("POD_CIDRS"), ExtraCIDRs: os.Getenv("EXTRA_CIDRS"), GatewayUpstreamDNSIP: os.Getenv("GATEWAY_UPSTREAM_DNS_IP"), GatewayUpstreamProbeURL: os.Getenv("GATEWAY_UPSTREAM_PROBE_URL"),
	}
}

type GatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	APIReader  client.Reader
	Recorder   events.EventRecorder
	Options    Options
	HTTPClient *http.Client
}

// EndpointID remains stable for the lifetime of the pod and changes on recreation.
func EndpointID(pod *corev1.Pod) string {
	h := sha256.Sum256([]byte(string(pod.UID)))
	return hex.EncodeToString(h[:6])
}

// allocateID hashes UID, then checks all gateways for persisted collisions. Persist
// the allocation in status before creating resources; never reuse an occupied VNI.
func (r *GatewayReconciler) allocateID(ctx context.Context, gw *api.EgressGateway) (uint32, error) {
	var all api.EgressGatewayList
	if err := r.List(ctx, &all); err != nil {
		return 0, err
	}
	used := map[uint32]bool{}
	for i := range all.Items {
		g := &all.Items[i]
		if g.UID != gw.UID && g.Status.GatewayID != 0 {
			used[g.Status.GatewayID] = true
		}
	}
	if id := gw.Status.GatewayID; id != 0 {
		if id > 0xffffff || used[id] {
			return 0, fmt.Errorf("gatewayID collision or invalid allocation")
		}
		return id, nil
	}
	sum := sha256.Sum256([]byte(string(gw.UID)))
	candidate := binary.BigEndian.Uint32(sum[:4])%0xffffff + 1
	for used[candidate] {
		candidate = candidate%0xffffff + 1
	}
	return candidate, nil
}

func (r *GatewayReconciler) selected(ctx context.Context, gw *api.EgressGateway) ([]netip.Addr, error) {
	// Admission denies every namespace when no selector is configured. The
	// forwarding allowlist must use the same default-deny decision; selecting
	// everything here would bypass the gateway's anti-spoof identity boundary.
	if gw.Spec.AllowedNamespaces.NamespaceSelector == nil {
		return nil, nil
	}
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return nil, err
	}
	selector, err := metav1.LabelSelectorAsSelector(gw.Spec.AllowedNamespaces.NamespaceSelector)
	if err != nil {
		return nil, err
	}
	seen := map[netip.Addr]bool{}
	var ips []netip.Addr
	for _, ns := range namespaces.Items {
		if !selector.Matches(labels.Set(ns.Labels)) {
			continue
		}
		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.InNamespace(ns.Name), client.MatchingLabels{GatewayLabel: gw.Name}); err != nil {
			return nil, err
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.DeletionTimestamp != nil || p.Labels[IdentityLabel] != "" {
				continue
			}
			target := p.Labels[GatewayNamespace]
			if target == "" {
				target = p.Annotations[GatewayNamespace]
			}
			if target == "" {
				target = r.Options.OperatorNamespace
			}
			if target != gw.Namespace {
				continue
			}
			// The node agent, not the capability-free wait-init, owns Pod
			// readiness while driver=agent. The wait-init cannot terminate until
			// the agent has installed its marker; interpreting it as failed init
			// would overwrite the agent's correct datapath-ready annotation.
			if r.Options.Driver != "agent" {
				if err := r.reconcilePodReadiness(ctx, p); err != nil {
					return nil, err
				}
			}
			ip, err := netip.ParseAddr(p.Status.PodIP)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if !seen[ip] {
				ips = append(ips, ip)
				seen[ip] = true
			}
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	return ips, nil
}

// reconcilePodReadiness only promotes webhook-injected workload pods after
// Kubernetes reports the specific datapath init container exited successfully.
// A PodIP alone (including on Pending pods) is never proof of initialized routes.
func (r *GatewayReconciler) reconcilePodReadiness(ctx context.Context, p *corev1.Pod) error {
	if _, injected := p.Annotations[datapathReadyAnnotation]; !injected {
		return nil
	}
	hasInit := false
	for _, c := range p.Spec.InitContainers {
		if c.Name == clientInitContainer {
			hasInit = true
			break
		}
	}
	state := "pending"
	if !hasInit {
		state = "error"
	} else {
		for _, s := range p.Status.InitContainerStatuses {
			if s.Name != clientInitContainer {
				continue
			}
			if s.State.Terminated != nil {
				if s.State.Terminated.ExitCode == 0 {
					state = "true"
				} else {
					state = "error"
				}
			} else if s.State.Waiting != nil && (s.State.Waiting.Reason == "CrashLoopBackOff" || s.State.Waiting.Reason == "CreateContainerConfigError" || s.State.Waiting.Reason == "CreateContainerError" || s.State.Waiting.Reason == "ImagePullBackOff" || s.State.Waiting.Reason == "ErrImagePull") {
				state = "error"
			}
			break
		}
	}
	if state == "true" {
		ip, e := netip.ParseAddr(p.Status.PodIP)
		if e != nil || !ip.Is4() || ip.IsUnspecified() {
			state = "pending"
		}
	}
	if p.Annotations[datapathReadyAnnotation] == state {
		return nil
	}
	old := p.DeepCopy()
	p.Annotations[datapathReadyAnnotation] = state
	if err := r.Patch(ctx, p, client.MergeFrom(old)); err != nil {
		return fmt.Errorf("patch selected Pod readiness %s/%s: %w", p.Namespace, p.Name, err)
	}
	if state == "error" && r.Recorder != nil {
		r.Recorder.Eventf(p, nil, corev1.EventTypeWarning, "DatapathInitFailed", "CheckInit", "ratatoskr-init container did not complete successfully")
	}
	return nil
}

func (r *GatewayReconciler) status(ctx context.Context, gw *api.EgressGateway, ready bool, reason, message string) error {
	gw.Status.ObservedGeneration = gw.Generation
	switch {
	case ready:
		gw.Status.Phase = "Ready"
	case reason == "Unsupported":
		gw.Status.Phase = "Unsupported"
		gw.Status.ReadyReplicas = 0
	default:
		gw.Status.Phase = "Pending"
	}
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "Ready", Status: condition(ready), Reason: reason, Message: message, ObservedGeneration: gw.Generation})
	var current api.EgressGateway
	if err := r.Get(ctx, client.ObjectKeyFromObject(gw), &current); err != nil {
		return err
	}
	if reflect.DeepEqual(current.Status, gw.Status) {
		return nil
	}
	return r.Status().Update(ctx, gw)
}
func condition(b bool) metav1.ConditionStatus {
	if b {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

// gatewayFailureReason is a fixed public vocabulary. API/provider errors may
// include credentials or profile bytes: never place their text in Events,
// Gateway status or structured logs. Unknown reasons use one generic category.
func gatewayFailureReason(reason string) string {
	switch reason {
	case "AllocationFailed", "InvalidConfiguration", "Unsupported", "SecretUnavailable",
		"SecretInvalid", "ExclusionDiscoveryFailed", "DNSUnavailable", "SelectionFailed",
		"RenderFailed", "ApplyFailed", "DNSCleanupFailed", "GatewayPodListFailed",
		"GatewayPodIdentityFailed":
		return reason
	default:
		return "ReconcileFailed"
	}
}

func (r *GatewayReconciler) failure(ctx context.Context, gw *api.EgressGateway, reason string, cause error) (ctrl.Result, error) {
	reason = gatewayFailureReason(reason)
	message := "Gateway reconciliation blocked at " + reason + "; inspect controller and owned resources."
	category := ""
	if reason == "ExclusionDiscoveryFailed" {
		category, message = exclusionAdvice(cause)
	}
	// Log only fixed categories/advice: provider/API errors can contain private data.
	log.FromContext(ctx).Info("gateway reconcile blocked", "reason", reason, "exclusionCategory", category, "advice", message)
	previous := meta.FindStatusCondition(gw.Status.Conditions, "Ready")
	transition := previous == nil || previous.Status != metav1.ConditionFalse ||
		previous.Reason != reason || previous.Message != message || previous.ObservedGeneration != gw.Generation
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: reason, Status: metav1.ConditionTrue, Reason: reason, Message: message, ObservedGeneration: gw.Generation})
	if e := r.status(ctx, gw, false, reason, message); e != nil {
		return ctrl.Result{}, e
	}
	if transition && r.Recorder != nil {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", message)
	}
	return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
}

func validPublishedIdentity(caPEM, key string) bool {
	parsedKey, err := wgtypes.ParseKey(key)
	if err != nil || parsedKey == (wgtypes.Key{}) || len(caPEM) == 0 || len(caPEM) >= 4096 {
		return false
	}
	block, rest := pem.Decode([]byte(caPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || len(block.Headers) != 0 {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil && time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter)
}

// managedGatewayPod binds published WireGuard TLS/WG keys to a Pod created by
// this gateway's controlled Deployment, not merely a spoofable matching label.
// Kubernetes Deployment Pods are owned by ReplicaSets, not directly by the CRD.
func (r *GatewayReconciler) managedGatewayPod(ctx context.Context, gw *api.EgressGateway, pod *corev1.Pod) (bool, error) {
	if pod.Namespace != gw.Namespace || pod.Labels[IdentityLabel] != gw.Name || pod.Labels[ownerUIDLabel] != string(gw.UID) || (gw.Spec.Encryption == "wireguard" && pod.Spec.ServiceAccountName != "ratatoskr-gateway") {
		return false, nil
	}
	rsRef := metav1.GetControllerOf(pod)
	if rsRef == nil || rsRef.Kind != "ReplicaSet" || rsRef.APIVersion != "apps/v1" {
		return false, nil
	}
	var rs appsv1.ReplicaSet
	if err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: rsRef.Name}, &rs); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if rs.UID != rsRef.UID {
		return false, nil
	}
	depRef := metav1.GetControllerOf(&rs)
	if depRef == nil || depRef.Kind != "Deployment" || depRef.APIVersion != "apps/v1" {
		return false, nil
	}
	var dep appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: depRef.Name}, &dep); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if dep.UID != depRef.UID || dep.Name != gw.Name || !metav1.IsControlledBy(&dep, gw) {
		return false, nil
	}
	return true, nil
}

// expectedGatewayConfigHash hashes the exact bytes that Kubernetes projects
// from our owner-controlled ConfigMap; decoding/re-encoding would change the
// digest and could falsely acknowledge a configuration the Pod never applied.
func expectedGatewayConfigHash(objects []client.Object, gw *api.EgressGateway) (string, error) {
	for _, object := range objects {
		cm, ok := object.(*corev1.ConfigMap)
		if !ok || cm.Name != gw.Name || cm.Namespace != gw.Namespace || !metav1.IsControlledBy(cm, gw) {
			continue
		}
		raw, exists := cm.Data["gateway.json"]
		if !exists || raw == "" {
			return "", fmt.Errorf("rendered gateway.json is missing")
		}
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:]), nil
	}
	return "", fmt.Errorf("owner-controlled rendered gateway ConfigMap unavailable")
}

// validGatewayAck never trusts a stale /info response from an old Pod at a
// reused PodIP. An ack is published only for the current managed Pod UID and
// the exact desired ConfigMap bytes; upstream health is evaluated separately.
func validGatewayAck(pod *corev1.Pod, info gatewayInfo, expectedHash string) bool {
	if pod == nil || pod.UID == "" || expectedHash == "" || len(expectedHash) != 64 {
		return false
	}
	return info.PodUID == string(pod.UID) && info.AppliedClientConfigHash == expectedHash
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var gw api.EgressGateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if gw.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	id, err := r.allocateID(ctx, &gw)
	if err != nil {
		return r.failure(ctx, &gw, "AllocationFailed", err)
	}
	if gw.Status.GatewayID != id {
		gw.Status.GatewayID = id
		if err := r.Status().Update(ctx, &gw); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}
	if r.Options.OperatorNamespace == "" || r.Options.GatewayImage == "" || r.Options.OpenVPNImage == "" {
		return r.failure(ctx, &gw, "InvalidConfiguration", fmt.Errorf("operator namespace and gateway/upstream images are required"))
	}
	if (gw.Spec.Replicas < 0 || gw.Spec.Replicas > 32) || (gw.Spec.Encryption != "" && gw.Spec.Encryption != "none" && gw.Spec.Encryption != "wireguard") || (gw.Spec.Encryption == "wireguard" && gw.Namespace != r.Options.OperatorNamespace) || gw.Spec.Upstream.Type != "openvpn" || gw.Spec.Upstream.Image != "" || (gw.Spec.DNS.Mode != "" && gw.Spec.DNS.Mode != "cluster" && gw.Spec.DNS.Mode != "gateway") || (r.Options.Datapath != "" && r.Options.Datapath != "iproute" && r.Options.Datapath != "ebpf") || (r.Options.Datapath == "ebpf" && gw.Spec.Encryption == "wireguard") || (r.Options.Driver != "" && r.Options.Driver != "init" && r.Options.Driver != "agent") {
		return r.unsupported(ctx, &gw, "requested replicas, encryption, upstream image/type, driver or datapath not supported")
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Spec.Upstream.SecretRef.Name}, &secret); err != nil {
		return r.block(ctx, &gw, "SecretUnavailable", fmt.Errorf("upstream Secret unavailable: %w", err))
	}
	if len(secret.Data["client.ovpn"]) == 0 {
		return r.block(ctx, &gw, "SecretInvalid", fmt.Errorf("upstream Secret missing client.ovpn"))
	}
	exclusions, dnsIP, err := r.collectExclusions(ctx, &gw)
	if err != nil {
		return r.block(ctx, &gw, "ExclusionDiscoveryFailed", err)
	}
	gw.Status.EffectiveExclusions = exclusions
	gw.Status.MTU = api.GatewayMTUStatus{} // Set only from measured /info link attributes below.
	if gw.Spec.DNS.Mode == "gateway" && dnsIP == "" {
		return r.block(ctx, &gw, "DNSUnavailable", fmt.Errorf("kube-system/kube-dns has no IPv4 ClusterIP"))
	}
	ips, err := r.selected(ctx, &gw)
	if err != nil {
		return r.block(ctx, &gw, "SelectionFailed", err)
	}
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "Unsupported", Status: metav1.ConditionFalse, Reason: "Supported", Message: "gateway configuration supported", ObservedGeneration: gw.Generation})
	resources, err := r.render(&gw, ips, dnsIP)
	if err != nil {
		return r.block(ctx, &gw, "RenderFailed", err)
	}
	expectedAppliedHash, err := expectedGatewayConfigHash(resources, &gw)
	if err != nil {
		return r.block(ctx, &gw, "RenderFailed", err)
	}
	for _, obj := range resources {
		if err := r.apply(ctx, &gw, obj); err != nil {
			return r.block(ctx, &gw, "ApplyFailed", err)
		}
	}
	if gw.Spec.DNS.Mode != "gateway" {
		var oldDNS corev1.Service
		err := r.Get(ctx, types.NamespacedName{Name: gw.Name + "-dns", Namespace: gw.Namespace}, &oldDNS)
		if err == nil && metav1.IsControlledBy(&oldDNS, &gw) {
			if err = r.Delete(ctx, &oldDNS); err != nil {
				return r.block(ctx, &gw, "DNSCleanupFailed", err)
			}
		} else if client.IgnoreNotFound(err) != nil {
			return r.block(ctx, &gw, "DNSCleanupFailed", err)
		}
	}
	if gw.Spec.DNS.Mode == "gateway" {
		var dnsService corev1.Service
		if err := r.Get(ctx, types.NamespacedName{Name: gw.Name + "-dns", Namespace: gw.Namespace}, &dnsService); err != nil {
			return r.block(ctx, &gw, "DNSUnavailable", err)
		}
		ip, err := netip.ParseAddr(dnsService.Spec.ClusterIP)
		if err != nil || !ip.Is4() || ip.IsUnspecified() {
			return r.block(ctx, &gw, "DNSUnavailable", fmt.Errorf("gateway DNS Service has no usable IPv4 ClusterIP"))
		}
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace), client.MatchingLabels{ownerUIDLabel: string(gw.UID)}); err != nil {
		return r.block(ctx, &gw, "GatewayPodListFailed", err)
	}
	oldEndpoints := append([]api.GatewayEndpoint(nil), gw.Status.Endpoints...)
	gw.Status.Endpoints = nil
	gw.Status.ReadyReplicas = 0
	seenPodIPs := make(map[string]bool, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.PodIP == "" {
			continue
		}
		// Labels are not proof of ownership. A matching but unmanaged Pod must
		// never be published as a gateway endpoint or counted as ready.
		managed, e := r.managedGatewayPod(ctx, &gw, p)
		if e != nil {
			return r.block(ctx, &gw, "GatewayPodIdentityFailed", e)
		}
		if !managed {
			continue
		}
		addr, e := netip.ParseAddr(p.Status.PodIP)
		if e != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() || seenPodIPs[p.Status.PodIP] {
			continue
		}
		seenPodIPs[p.Status.PodIP] = true
		// Status is rebuilt from current managed Pods on every reconcile. The
		// Pod UID is public even before an ack; the hash remains empty unless this
		// exact Pod has applied the latest owner-controlled ConfigMap bytes.
		ep := api.GatewayEndpoint{PodName: p.Name, PodIP: p.Status.PodIP, PodUID: string(p.UID)}
		if podReady(p) {
			info, e := r.info(ctx, p.Status.PodIP)
			if e == nil && info.Ready && net.ParseIP(info.ExitIP) != nil && (info.PodUID == "" || info.PodUID == string(p.UID)) {
				publicIdentityReady := true
				if gw.Spec.Encryption == "wireguard" {
					// A public key/certificate from an arbitrary Pod is not a trust
					// anchor: bind it to the managed Deployment/Pod owner UID.
					managed, e := r.managedGatewayPod(ctx, &gw, p)
					if e != nil {
						return r.block(ctx, &gw, "GatewayPodIdentityFailed", e)
					}
					publicIdentityReady = managed && validPublishedIdentity(p.Annotations[registrationCAAnnotation], p.Annotations[wireguardKeyAnnotation]) && info.WireguardMTU >= 576
				}
				if validGatewayAck(p, info, expectedAppliedHash) {
					ep.AppliedClientConfigHash = expectedAppliedHash
				}
				if info.measured() && publicIdentityReady {
					// Use the smallest healthy replica budget so a client moved to
					// another endpoint cannot exceed that replica's upstream MTU.
					if gw.Status.MTU.EffectiveMTU == 0 || info.EffectiveMTU < gw.Status.MTU.EffectiveMTU {
						gw.Status.MTU = api.GatewayMTUStatus{GeneveMTU: info.GeneveMTU, WireguardMTU: info.WireguardMTU, EffectiveMTU: info.EffectiveMTU, MSS: info.MSS}
					}
					meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "MTUUnknown", Status: metav1.ConditionFalse, Reason: "Measured", Message: "Gateway reports measured link MTUs", ObservedGeneration: gw.Generation})
					if info.EffectiveMTU < 1280 {
						if !meta.IsStatusConditionTrue(gw.Status.Conditions, "MTUWarning") && r.Recorder != nil {
							r.Recorder.Eventf(&gw, nil, corev1.EventTypeWarning, "BelowIPv6Minimum", "Measure", "effective MTU below 1280; IPv4 remains supported")
						}
						meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "MTUWarning", Status: metav1.ConditionTrue, Reason: "BelowIPv6Minimum", Message: "Measured effective MTU supports IPv4 but is below IPv6 minimum 1280", ObservedGeneration: gw.Generation})
					} else {
						meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "MTUWarning", Status: metav1.ConditionFalse, Reason: "Safe", Message: "Measured effective MTU at least 1280", ObservedGeneration: gw.Generation})
					}
					ep.UpstreamHealthy = true
					ep.UpstreamExitIP = info.ExitIP
					if gw.Spec.Encryption == "wireguard" {
						ep.WireguardPublicKey = p.Annotations[wireguardKeyAnnotation]
						ep.RegistrationCACert = p.Annotations[registrationCAAnnotation]
					}
					gw.Status.ReadyReplicas++
				} else {
					if !meta.IsStatusConditionTrue(gw.Status.Conditions, "MTUUnknown") && r.Recorder != nil {
						r.Recorder.Eventf(&gw, nil, corev1.EventTypeWarning, "MTUUnknown", "Measure", "gateway did not report consistent measured link MTUs")
					}
					meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "MTUUnknown", Status: metav1.ConditionTrue, Reason: "InvalidMeasurement", Message: "gateway did not report consistent measured pod/GENEVE/upstream MTU", ObservedGeneration: gw.Generation})
				}
			}
		}
		gw.Status.Endpoints = append(gw.Status.Endpoints, ep)
	}
	sort.Slice(gw.Status.Endpoints, func(i, j int) bool { return gw.Status.Endpoints[i].PodName < gw.Status.Endpoints[j].PodName })
	// An init pod retains its original fixed GENEVE remote (and WG trust
	// root). An agent-managed pod can update in place. Evaluate every former
	// healthy endpoint, not merely the first sorted Pod name.
	if r.Options.Driver != "agent" && len(ips) > 0 && endpointRestartRequired(oldEndpoints, gw.Status.Endpoints, gw.Spec.Encryption == "wireguard") {
		meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "ClientRestartRequired", Status: metav1.ConditionTrue, Reason: "EndpointChangedOrLost", Message: "a gateway endpoint or WireGuard identity changed; roll out init-driver clients pinned to it", ObservedGeneration: gw.Generation})
		if r.Recorder != nil {
			r.Recorder.Eventf(&gw, nil, corev1.EventTypeWarning, "ClientRestartRequired", "Rollout", "Gateway endpoint changed; roll out affected init-driver clients")
		}
	} else {
		meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "ClientRestartRequired", Status: metav1.ConditionFalse, Reason: "AgentReconcilesOrNoChange", Message: "no init-driver client rollout required", ObservedGeneration: gw.Generation})
	}
	ready := gw.Status.ReadyReplicas > 0
	if err := r.status(ctx, &gw, ready, "GatewayHealth", "gateway Pod and upstream must be healthy"); err != nil {
		return ctrl.Result{}, err
	}
	if r.Options.Driver != "agent" {
		var current api.EgressGateway
		if err := r.Get(ctx, client.ObjectKeyFromObject(&gw), &current); err != nil {
			return ctrl.Result{}, err
		}
		var desiredConfig *corev1.ConfigMap
		for _, obj := range resources {
			if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Name == gw.Name {
				desiredConfig = cm
				break
			}
		}
		if desiredConfig == nil {
			return ctrl.Result{}, fmt.Errorf("owner-controlled gateway config unavailable for init ack")
		}
		if err := r.reconcileInitAppliedAck(ctx, &current, desiredConfig.Data["gateway.json"]); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

// endpointRestartRequired compares healthy endpoints by PodIP, not Pod name.
// Added replicas do not invalidate a pinned init client, but removal, loss
// of health, or a changed authenticated identity does.
func endpointRestartRequired(before, after []api.GatewayEndpoint, encrypted bool) bool {
	current := make(map[string]api.GatewayEndpoint, len(after))
	for _, e := range after {
		if e.UpstreamHealthy {
			current[e.PodIP] = e
		}
	}
	for _, old := range before {
		if !old.UpstreamHealthy {
			continue
		}
		now, ok := current[old.PodIP]
		if !ok || encrypted && (old.WireguardPublicKey != now.WireguardPublicKey || old.RegistrationCACert != now.RegistrationCACert) {
			return true
		}
	}
	return false
}

func (r *GatewayReconciler) block(ctx context.Context, gw *api.EgressGateway, reason string, err error) (ctrl.Result, error) {
	// A formerly supported gateway must not keep forwarding under a failed contract.
	var deployment appsv1.Deployment
	e := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &deployment)
	if e == nil && metav1.IsControlledBy(&deployment, gw) {
		if e = r.Delete(ctx, &deployment); e != nil {
			return ctrl.Result{}, e
		}
	} else if client.IgnoreNotFound(e) != nil {
		return ctrl.Result{}, e
	}
	gw.Status.Endpoints = nil
	result, failureErr := r.failure(ctx, gw, reason, err)
	if failureErr != nil {
		return result, failureErr
	}
	if err := r.reconcileInitAppliedAck(ctx, gw, ""); err != nil {
		return ctrl.Result{}, err
	}
	return result, nil
}
func (r *GatewayReconciler) unsupported(ctx context.Context, gw *api.EgressGateway, why string) (ctrl.Result, error) {
	return r.block(ctx, gw, "Unsupported", fmt.Errorf("%s", why))
}
func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

type gatewayInfo struct {
	ExitIP                  string `json:"exitIP"`
	Ready                   bool   `json:"ready"`
	PodMTU                  int32  `json:"podMTU"`
	GeneveMTU               int32  `json:"geneveMTU"`
	WireguardMTU            int32  `json:"wireguardMTU"`
	UpstreamMTU             int32  `json:"upstreamMTU"`
	EffectiveMTU            int32  `json:"effectiveMTU"`
	MSS                     int32  `json:"mss"`
	PodUID                  string `json:"podUID"`
	AppliedClientConfigHash string `json:"appliedClientConfigHash"`
}

func (i gatewayInfo) measured() bool {
	return i.PodMTU >= 576 && i.GeneveMTU >= 576 && i.UpstreamMTU >= 576 && i.GeneveMTU <= i.PodMTU && i.EffectiveMTU == min(i.GeneveMTU, i.UpstreamMTU) && i.MSS == i.EffectiveMTU-40
}

func (r *GatewayReconciler) info(ctx context.Context, ip string) (gatewayInfo, error) {
	var info gatewayInfo
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return info, fmt.Errorf("invalid gateway PodIP")
	}
	c := r.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(ip, "9900")+"/info", nil)
	if err != nil {
		return info, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("gateway info unhealthy")
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info)
	return info, err
}
func (r *GatewayReconciler) apply(ctx context.Context, gw *api.EgressGateway, obj client.Object) error {
	key := client.ObjectKeyFromObject(obj)
	existing := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, key, existing)
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	if err != nil {
		return r.Create(ctx, obj)
	}
	if !metav1.IsControlledBy(existing, gw) {
		return fmt.Errorf("resource %s is not owned by gateway", key)
	}
	switch desired := obj.(type) {
	case *corev1.ConfigMap:
		old := existing.(*corev1.ConfigMap)
		if reflect.DeepEqual(old.Data, desired.Data) {
			return nil
		}
		old.Data = desired.Data
	case *corev1.Service:
		old := existing.(*corev1.Service)
		if reflect.DeepEqual(old.Spec.Ports, desired.Spec.Ports) && reflect.DeepEqual(old.Spec.Selector, desired.Spec.Selector) {
			return nil
		}
		old.Spec.Ports = desired.Spec.Ports
		old.Spec.Selector = desired.Spec.Selector
	case *networkingv1.NetworkPolicy:
		old := existing.(*networkingv1.NetworkPolicy)
		if reflect.DeepEqual(old.Spec, desired.Spec) {
			return nil
		}
		old.Spec = desired.Spec
	case *appsv1.Deployment:
		old := existing.(*appsv1.Deployment)
		if reflect.DeepEqual(old.Spec, desired.Spec) {
			return nil
		}
		old.Spec = desired.Spec
	}
	return r.Update(ctx, existing)
}

func (r *GatewayReconciler) mapAll(ctx context.Context, _ client.Object) []reconcile.Request {
	var gateways api.EgressGatewayList
	if err := r.List(ctx, &gateways); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(gateways.Items))
	for _, g := range gateways.Items {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: g.Namespace, Name: g.Name}})
	}
	return out
}

// Secret reads are uncached GETs; do not watch/list Secrets.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&api.EgressGateway{}).Owns(&appsv1.Deployment{}).Owns(&corev1.ConfigMap{}).Owns(&corev1.Service{}).Owns(&networkingv1.NetworkPolicy{}).Owns(&corev1.Pod{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapAll), builder.WithPredicates(predicate.Funcs{CreateFunc: func(event.CreateEvent) bool { return true }, DeleteFunc: func(event.DeleteEvent) bool { return true }, UpdateFunc: func(e event.UpdateEvent) bool {
			return !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) || !reflect.DeepEqual(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations()) || !reflect.DeepEqual(e.ObjectOld.(*corev1.Pod).Status, e.ObjectNew.(*corev1.Pod).Status)
		}})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Watches(&api.EgressPolicy{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Complete(r)
}
