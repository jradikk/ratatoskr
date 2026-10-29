// Package controller renders and reconciles the fail-closed M2 gateway workload.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	GatewayLabel     = "ratatoskr.skaldhall.io/gateway"
	GatewayNamespace = "ratatoskr.skaldhall.io/gateway-namespace"
	IdentityLabel    = "ratatoskr.skaldhall.io/gateway-name"
	ownerUIDLabel    = "ratatoskr.skaldhall.io/gateway-uid"
)

type Options struct {
	OperatorNamespace, GatewayImage, OpenVPNImage, ImagePullPolicy, Driver, Datapath, ClusterDomain, ServiceCIDRs, PodCIDRs string
}

func OptionsFromEnv() Options {
	return Options{
		OperatorNamespace: os.Getenv("OPERATOR_NAMESPACE"), GatewayImage: os.Getenv("GATEWAY_IMAGE"), OpenVPNImage: os.Getenv("OPENVPN_IMAGE"), ImagePullPolicy: os.Getenv("IMAGE_PULL_POLICY"), Driver: os.Getenv("DRIVER"), Datapath: os.Getenv("DATAPATH"), ClusterDomain: os.Getenv("CLUSTER_DOMAIN"), ServiceCIDRs: os.Getenv("SERVICE_CIDRS"), PodCIDRs: os.Getenv("POD_CIDRS"),
	}
}

type GatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
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
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return nil, err
	}
	selector := labels.Everything()
	if gw.Spec.AllowedNamespaces.NamespaceSelector != nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(gw.Spec.AllowedNamespaces.NamespaceSelector)
		if err != nil {
			return nil, err
		}
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
		gw.Status.ReadyReplicas = 0
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
func (r *GatewayReconciler) failure(ctx context.Context, gw *api.EgressGateway, reason string, err error) (ctrl.Result, error) {
	log.FromContext(ctx).Error(err, "gateway reconcile failed", "gateway", gw.Namespace+"/"+gw.Name, "reason", reason)
	if r.Recorder != nil {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", err.Error())
	}
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: reason, Status: metav1.ConditionTrue, Reason: reason, Message: err.Error(), ObservedGeneration: gw.Generation})
	if e := r.status(ctx, gw, false, reason, err.Error()); e != nil {
		return ctrl.Result{}, e
	}
	return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
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
	var policies api.EgressPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return ctrl.Result{}, err
	}
	for _, p := range policies.Items {
		ns := p.Spec.GatewayRef.Namespace
		if ns == "" {
			ns = r.Options.OperatorNamespace
		}
		if p.Spec.GatewayRef.Name == gw.Name && ns == gw.Namespace {
			return r.unsupported(ctx, &gw, "EgressPolicy compilation requires M3")
		}
	}
	if (gw.Spec.Replicas != 0 && gw.Spec.Replicas != 1) || (gw.Spec.Encryption != "" && gw.Spec.Encryption != "none") || gw.Spec.Upstream.Type != "openvpn" || gw.Spec.Upstream.Image != "" || (gw.Spec.DNS.Mode != "" && gw.Spec.DNS.Mode != "cluster") || (r.Options.Datapath != "" && r.Options.Datapath != "iproute") || (r.Options.Driver != "" && r.Options.Driver != "init") {
		return r.unsupported(ctx, &gw, "requested replicas, encryption, upstream image/type, DNS, driver or datapath not supported in M2")
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Spec.Upstream.SecretRef.Name}, &secret); err != nil {
		return r.block(ctx, &gw, "SecretUnavailable", fmt.Errorf("upstream Secret unavailable: %w", err))
	}
	if len(secret.Data["client.ovpn"]) == 0 {
		return r.block(ctx, &gw, "SecretInvalid", fmt.Errorf("upstream Secret missing client.ovpn"))
	}
	ips, err := r.selected(ctx, &gw)
	if err != nil {
		return r.block(ctx, &gw, "SelectionFailed", err)
	}
	for _, raw := range []string{r.Options.ServiceCIDRs, r.Options.PodCIDRs} {
		for _, cidr := range strings.Split(raw, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			p, e := netip.ParsePrefix(cidr)
			if e != nil || !p.Addr().Is4() {
				return r.block(ctx, &gw, "InvalidClusterCIDR", fmt.Errorf("invalid IPv4 cluster CIDR"))
			}
		}
	}
	gw.Status.EffectiveExclusions = parseCIDRs(r.Options.ServiceCIDRs, r.Options.PodCIDRs, strings.Join(gw.Spec.Exclusions.ExtraCIDRs, ","))
	for _, raw := range gw.Spec.Exclusions.ExtraCIDRs {
		p, e := netip.ParsePrefix(raw)
		if e != nil || !p.Addr().Is4() {
			return r.block(ctx, &gw, "InvalidExclusion", fmt.Errorf("invalid IPv4 exclusion CIDR"))
		}
	}
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "Unsupported", Status: metav1.ConditionFalse, Reason: "Supported", Message: "M2 gateway configuration supported", ObservedGeneration: gw.Generation})
	resources, err := r.render(&gw, ips)
	if err != nil {
		return r.block(ctx, &gw, "RenderFailed", err)
	}
	for _, obj := range resources {
		if err := r.apply(ctx, &gw, obj); err != nil {
			return r.block(ctx, &gw, "ApplyFailed", err)
		}
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace), client.MatchingLabels{ownerUIDLabel: string(gw.UID)}); err != nil {
		return ctrl.Result{}, err
	}
	oldIP := ""
	if len(gw.Status.Endpoints) > 0 {
		oldIP = gw.Status.Endpoints[0].PodIP
	}
	gw.Status.Endpoints = nil
	gw.Status.ReadyReplicas = 0
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.PodIP == "" {
			continue
		}
		ep := api.GatewayEndpoint{PodName: p.Name, PodIP: p.Status.PodIP}
		if podReady(p) {
			info, e := r.info(ctx, p.Status.PodIP)
			if e == nil && info.Ready && net.ParseIP(info.ExitIP) != nil {
				ep.UpstreamHealthy = true
				ep.UpstreamExitIP = info.ExitIP
				gw.Status.ReadyReplicas++
			}
		}
		gw.Status.Endpoints = append(gw.Status.Endpoints, ep)
	}
	sort.Slice(gw.Status.Endpoints, func(i, j int) bool { return gw.Status.Endpoints[i].PodName < gw.Status.Endpoints[j].PodName })
	newIP := ""
	if len(gw.Status.Endpoints) > 0 {
		newIP = gw.Status.Endpoints[0].PodIP
	}
	if oldIP != "" && oldIP != newIP && len(ips) > 0 {
		meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "ClientRestartRequired", Status: metav1.ConditionTrue, Reason: "GatewayPodIPChangedOrLost", Message: "Gateway PodIP changed or was lost; selected fixed-remote clients may require rollout; M2 cannot update running client netns", ObservedGeneration: gw.Generation})
		if r.Recorder != nil {
			r.Recorder.Eventf(&gw, nil, corev1.EventTypeWarning, "ClientRestartRequired", "Rollout", "Gateway PodIP changed; roll out selected client pods")
		}
	}
	if len(ips) == 0 {
		meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{Type: "ClientRestartRequired", Status: metav1.ConditionFalse, Reason: "NoSelectedClients", Message: "No selected client pods need rollout", ObservedGeneration: gw.Generation})
	}
	ready := gw.Status.ReadyReplicas == 1
	if err := r.status(ctx, &gw, ready, "GatewayHealth", "gateway Pod and upstream must be healthy"); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
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
	return r.failure(ctx, gw, reason, err)
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
	ExitIP string `json:"exitIP"`
	Ready  bool   `json:"ready"`
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
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&api.EgressGateway{}).Owns(&appsv1.Deployment{}).Owns(&corev1.ConfigMap{}).Owns(&corev1.Service{}).Owns(&corev1.Pod{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapAll), builder.WithPredicates(predicate.Funcs{CreateFunc: func(event.CreateEvent) bool { return true }, DeleteFunc: func(event.DeleteEvent) bool { return true }, UpdateFunc: func(e event.UpdateEvent) bool {
			return !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) || !reflect.DeepEqual(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations()) || !reflect.DeepEqual(e.ObjectOld.(*corev1.Pod).Status, e.ObjectNew.(*corev1.Pod).Status)
		}})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Watches(&api.EgressPolicy{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.mapAll)).Complete(r)
}

func parseCIDRs(parts ...string) []api.EffectiveExclusion {
	seen := map[string]bool{}
	out := []api.EffectiveExclusion{}
	for i, part := range parts {
		source := "extra"
		if i == 0 {
			source = "serviceCIDR"
		}
		if i == 1 {
			source = "podCIDR"
		}
		for _, s := range strings.Split(part, ",") {
			s = strings.TrimSpace(s)
			p, e := netip.ParsePrefix(s)
			if e == nil && p.Addr().Is4() && !seen[p.Masked().String()] {
				seen[p.Masked().String()] = true
				out = append(out, api.EffectiveExclusion{CIDR: p.Masked().String(), Source: source})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}
