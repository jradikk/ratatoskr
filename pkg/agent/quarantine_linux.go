//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Quarantine categories are fixed agent-authored values, not error text or
// user-controlled annotations. They explain why a Pod must be recreated.
const (
	quarantineNamespaceRead     = "NamespaceReadFailed"
	quarantineGatewayRead       = "GatewayReadFailed"
	quarantinePolicyRead        = "PolicyReadFailed"
	quarantineAuthorization     = "AuthorizationDenied"
	quarantineDomainPolicy      = "DomainPolicyChanged"
	quarantineDomainRestore     = "DomainStateRestoreFailed"
	quarantineDomainRedirect    = "DNSRedirectFailed"
	quarantineDomainListener    = "DNSListenerFailed"
	quarantineDomainPersistence = "DNSStatePersistenceFailed"
	quarantineDomainRouting     = "DNSRouteApplyFailed"
	quarantineDomainRuntime     = "DNSRuntimeFailed"
)

func safeQuarantineReason(reason string) string {
	switch reason {
	case quarantineNamespaceRead, quarantineGatewayRead, quarantinePolicyRead,
		quarantineAuthorization, quarantineDomainPolicy, quarantineDomainRestore,
		quarantineDomainRedirect, quarantineDomainListener, quarantineDomainPersistence,
		quarantineDomainRouting, quarantineDomainRuntime:
		return reason
	default:
		return "UnknownQuarantine"
	}
}

// quarantineError never includes a raw Kubernetes/DNS/CRI error. Its category
// is safe for node logs, while status carries the immutable first reason.
func quarantineError(reason string) error {
	return fmt.Errorf("workload quarantined after %s; recreate Pod", safeQuarantineReason(reason))
}

func reasonForDomainCause(cause error) string {
	if cause == nil {
		return quarantineDomainRuntime
	}
	// Only authored sentinel phrases are admitted, never include the raw
	// diagnostic or suffix from an API/DNS/backend error in Pod metadata.
	switch cause.Error() {
	case "domain policy/Service changed; recreate selected Pod", "domain policy or resolver changed; rollout required", "domain sandbox or gateway replaced":
		return quarantineDomainPolicy
	case "DNS interception missing":
		return quarantineDomainRedirect
	case "owned DNS server stopped", "owned DNS listener startup timeout":
		return quarantineDomainListener
	default:
		return quarantineDomainRuntime
	}
}

func (r *Reconciler) recordQuarantine(ctx context.Context, pod *corev1.Pod, reason string) (already bool, err error) {
	if r.Client == nil || pod == nil {
		return false, errors.New("cannot persist quarantine reason")
	}
	reason = safeQuarantineReason(reason)
	// Re-read UID and first reason: the pre-fence Pod snapshot may be stale.
	var latest corev1.Pod
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(pod), &latest); err != nil {
		return false, errors.New("GET selected Pod for quarantine reason failed")
	}
	if latest.UID != pod.UID || latest.DeletionTimestamp != nil {
		return false, errors.New("selected Pod identity changed before quarantine record")
	}
	already = latest.Annotations[QuarantineReasonAnnotation] != ""
	if already && latest.Annotations[ReadyAnnotation] == "pending" {
		return true, nil
	}
	original := latest.DeepCopy()
	latest.Annotations = copyAnnotations(latest.Annotations)
	if !already {
		latest.Annotations[QuarantineReasonAnnotation] = reason
	}
	latest.Annotations[ReadyAnnotation] = "pending"
	if err := r.Client.Patch(ctx, &latest, client.MergeFrom(original)); err != nil {
		return already, errors.New("quarantine reason persistence failed")
	}
	pod.Annotations = copyAnnotations(latest.Annotations)
	return already, nil
}
