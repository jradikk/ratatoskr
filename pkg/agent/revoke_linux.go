//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
)

// quarantineUnknownAuthorization is irreversible within this sandbox. No
// agent-hash annotation is authentication: block the whole namespace instead
// of guessing a route table from a potentially forged stored config.
func quarantineUnknownAuthorization(target *os.File, podIP netip.Addr) error {
	return InNamespace(target, func() error {
		if err := verifyTargetPodIPv4(podIP); err != nil {
			return err
		}
		if err := ensureOutputDrop(ipv6GuardTable, nftables.TableFamilyIPv6); err != nil {
			return err
		}
		if err := ensureOutputDrop(quarantineTable, nftables.TableFamilyIPv4); err != nil {
			return err
		}
		return clearReadyMarker()
	})
}

type verifiedSandbox struct {
	target *os.File
	proof  sandboxProof
	close  func()
}

func (r *Reconciler) sandboxForRevocation(ctx context.Context, p *corev1.Pod) (verifiedSandbox, error) {
	if r.CRI == nil {
		return verifiedSandbox{}, errors.New("CRI client unavailable for revocation")
	}
	target, proof, err := Sandbox(ctx, r.CRI, p.Namespace, p.Name, string(p.UID), p.Status.PodIP)
	if err != nil {
		return verifiedSandbox{}, fmt.Errorf("verify sandbox for revocation: %w", err)
	}
	closeAll := func() { _ = target.Close(); _ = unix.Close(proof.pidfd) }
	if err = recheckSandbox(ctx, r.CRI, proof, target); err != nil {
		closeAll()
		return verifiedSandbox{}, err
	}
	return verifiedSandbox{target: target, proof: proof, close: closeAll}, nil
}

// revokeSelected fences a verified sandbox after authorization failure and
// publishes only an agent-authored reason, never the raw API/Secret error.
func (r *Reconciler) revokeSelected(ctx context.Context, p *corev1.Pod, reason string) error {
	reason = safeQuarantineReason(reason)
	if p == nil || p.UID == "" {
		return quarantineError(reason)
	}
	target, err := r.sandboxForRevocation(ctx, p)
	if err != nil {
		return errors.Join(quarantineError(reason), errors.New("sandbox verification failed before quarantine"))
	}
	defer target.close()
	ip, err := netip.ParseAddr(p.Status.PodIP)
	if err != nil {
		return errors.Join(quarantineError(reason), errors.New("selected PodIP invalid during revocation"))
	}
	if err = quarantineUnknownAuthorization(target.target, ip); err != nil {
		return errors.Join(quarantineError(reason), errors.New("namespace quarantine failed"))
	}
	already, err := r.recordQuarantine(ctx, p, reason)
	if err != nil {
		return errors.Join(quarantineError(reason), err)
	}
	if already {
		return nil // First cause is recorded; no repeat log/health storm.
	}
	return quarantineError(reason)
}
