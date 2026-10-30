//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type OwnPod struct{ Namespace, Name, UID, Node string }
type hostAnchor struct {
	fd   *os.File
	stat unix.Stat_t
}

var verifiedHost atomic.Pointer[hostAnchor]

// validateOwnPod binds the claimed downward-API identity to the uncached
// Kubernetes Pod object and verifies the environment variable sources.
func validateOwnPod(p *corev1.Pod, id OwnPod) error {
	if id.Namespace == "" || id.Name == "" || id.UID == "" || id.Node == "" || p == nil || p.Namespace != id.Namespace || p.Name != id.Name || string(p.UID) != id.UID || p.Spec.NodeName != id.Node || !p.Spec.HostNetwork || !p.Spec.HostPID || p.Spec.ServiceAccountName != "ratatoskr-agent" || p.DeletionTimestamp != nil {
		return errors.New("agent Pod identity, host namespaces, service account or lifecycle mismatch")
	}
	for _, container := range p.Spec.Containers {
		if container.Name != "agent" {
			continue
		}
		expected := map[string]string{"POD_NAMESPACE": "metadata.namespace", "POD_NAME": "metadata.name", "POD_UID": "metadata.uid", "NODE_NAME": "spec.nodeName"}
		for _, env := range container.Env {
			field, ok := expected[env.Name]
			if !ok {
				// Duplicate identity env declarations could shadow kubelet
				// fieldRefs at runtime; reject them even after a valid one.
				for _, identity := range []string{"POD_NAMESPACE", "POD_NAME", "POD_UID", "NODE_NAME"} {
					if env.Name == identity {
						return fmt.Errorf("duplicate agent identity env %s", env.Name)
					}
				}
				continue
			}
			if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.FieldRef == nil || env.ValueFrom.FieldRef.FieldPath != field || (env.ValueFrom.FieldRef.APIVersion != "" && env.ValueFrom.FieldRef.APIVersion != "v1") {
				return fmt.Errorf("agent %s must originate from the Downward API", env.Name)
			}
			delete(expected, env.Name)
		}
		if len(expected) == 0 {
			return nil
		}
	}
	return errors.New("agent Pod lacks exact Downward API identity fieldRefs")
}

func (r *Reconciler) VerifyOwnPod(ctx context.Context) error {
	if r.Client == nil {
		return errors.New("agent API client unavailable")
	}
	var pod corev1.Pod
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: r.Own.Namespace, Name: r.Own.Name}, &pod); err != nil {
		return fmt.Errorf("GET own agent Pod: %w", err)
	}
	return validateOwnPod(&pod, r.Own)
}

// Bootstrap must run once after authenticating the agent Pod and before CRI
// access. A pinned FD keeps the trusted host netns alive for this process.
func (r *Reconciler) Bootstrap(ctx context.Context) error {
	if verifiedHost.Load() != nil {
		return errors.New("host namespace already anchored")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := r.VerifyOwnPod(ctx); err != nil {
		return err
	}
	fd, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return fmt.Errorf("pin verified agent thread netns: %w", err)
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(fd.Fd()), &stat); err != nil {
		fd.Close()
		return err
	}
	if stat.Ino == 0 {
		fd.Close()
		return errors.New("invalid verified host namespace")
	}
	anchor := &hostAnchor{fd: fd, stat: stat}
	if !verifiedHost.CompareAndSwap(nil, anchor) {
		fd.Close()
		return errors.New("host namespace already anchored")
	}
	return nil
}
func hostStat() (unix.Stat_t, error) {
	a := verifiedHost.Load()
	if a == nil || a.fd == nil {
		return unix.Stat_t{}, errors.New("verified host namespace bootstrap required")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(a.fd.Fd()), &stat); err != nil {
		return stat, err
	}
	if !sameNetns(stat, a.stat) {
		return stat, errors.New("verified host namespace anchor changed")
	}
	return stat, nil
}
func checkThreadHost() error {
	host, err := hostStat()
	if err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &current); err != nil {
		return err
	}
	if !sameNetns(current, host) {
		return errors.New("agent thread not in verified host namespace")
	}
	return nil
}

// Keep the FD open for the process lifetime; no unverified re-bootstrap.
