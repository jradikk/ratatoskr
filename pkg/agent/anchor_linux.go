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

// The kubelet bind-mounts host PID1's nsfs network namespace at this fixed
// path. Workload CRI paths never derive from this file or any /proc PID path.
const hostNetnsMount = "/var/run/ratatoskr/host-netns"
const hostNetnsVolume = "host-netns"

func validHostAnchorMount(p *corev1.Pod) bool {
	if p == nil || len(p.Spec.Volumes) == 0 {
		return false
	}
	volumes := 0
	for _, v := range p.Spec.Volumes {
		if v.Name != hostNetnsVolume {
			continue
		}
		volumes++
		if v.HostPath == nil || v.HostPath.Path != "/proc/1/ns/net" || v.HostPath.Type == nil || *v.HostPath.Type != corev1.HostPathFile {
			return false
		}
	}
	if volumes != 1 {
		return false
	}
	for _, c := range p.Spec.Containers {
		mounts := 0
		for _, m := range c.VolumeMounts {
			if m.Name == hostNetnsVolume || m.MountPath == hostNetnsMount {
				mounts++
				if c.Name != "agent" || m.Name != hostNetnsVolume || m.MountPath != hostNetnsMount || !m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" || m.MountPropagation != nil {
					return false
				}
			}
		}
		if c.Name == "agent" {
			if mounts != 1 {
				return false
			}
		} else if mounts != 0 {
			return false
		}
	}
	return true
}

type namespaceAnchors struct {
	ownFD, hostFD     *os.File
	ownStat, hostStat unix.Stat_t
}

var verifiedNamespaces atomic.Pointer[namespaceAnchors]

// validateOwnPod binds the claimed downward-API identity to the uncached
// Kubernetes Pod object and verifies the environment variable sources.
func validateOwnPod(p *corev1.Pod, id OwnPod) error {
	if id.Namespace == "" || id.Name == "" || id.UID == "" || id.Node == "" || p == nil || p.Namespace != id.Namespace || p.Name != id.Name || string(p.UID) != id.UID || p.Spec.NodeName != id.Node || p.Spec.HostNetwork || !p.Spec.HostPID || p.Spec.ServiceAccountName != "ratatoskr-agent" || p.DeletionTimestamp != nil || !validHostAnchorMount(p) {
		return errors.New("agent Pod identity, separate network namespace, hostPID, service account or lifecycle mismatch")
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

// Bootstrap authenticates the agent Pod before pinning both its own separate
// network namespace and the read-only kubelet-provided host-PID-1 network
// namespace mount. /proc/1/ns/net is resolved by the kubelet on the node,
// not opened by this RuntimeDefault process (which may lack ptrace access).
// The mount is ONLY a forbidden anchor, never a fallback CRI workload path.
// Failure to open or validate either FD fails closed without new privileges.
func (r *Reconciler) Bootstrap(ctx context.Context) error {
	if verifiedNamespaces.Load() != nil {
		return errors.New("network namespaces already anchored")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := r.VerifyOwnPod(ctx); err != nil {
		return err
	}
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return fmt.Errorf("pin verified agent thread netns: %w", err)
	}
	defer func() {
		if own != nil {
			_ = own.Close()
		}
	}()
	host, err := openHostNetnsAnchor(hostNetnsMount)
	if err != nil {
		return fmt.Errorf("pin mounted host network namespace: %w", err)
	}
	defer func() {
		if host != nil {
			_ = host.Close()
		}
	}()
	anchor, err := validateAnchors(own, host)
	if err != nil {
		return err
	}
	if !verifiedNamespaces.CompareAndSwap(nil, anchor) {
		return errors.New("network namespaces already anchored")
	}
	own, host = nil, nil // Anchors stay pinned for the process lifetime.
	return nil
}

// openHostNetnsAnchor opens only the exact kubelet-mounted anchor. O_NOFOLLOW
// prevents a container-side symlink from replacing the trusted mountpoint;
// nsfs and network namespace type are checked independently below.
func openHostNetnsAnchor(path string) (*os.File, error) {
	if path != hostNetnsMount {
		return nil, errors.New("unrecognized host network namespace mount")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	host := os.NewFile(uintptr(fd), path)
	if err := validateNetworkNamespaceFD(host); err != nil {
		_ = host.Close()
		return nil, err
	}
	return host, nil
}

func validateAnchors(own, host *os.File) (*namespaceAnchors, error) {
	if err := validateNetworkNamespaceFD(own); err != nil {
		return nil, fmt.Errorf("verify own namespace: %w", err)
	}
	if err := validateNetworkNamespaceFD(host); err != nil {
		return nil, fmt.Errorf("verify host namespace: %w", err)
	}
	anchor := &namespaceAnchors{ownFD: own, hostFD: host}
	if err := unix.Fstat(int(own.Fd()), &anchor.ownStat); err != nil {
		return nil, err
	}
	if err := unix.Fstat(int(host.Fd()), &anchor.hostStat); err != nil {
		return nil, err
	}
	if anchor.ownStat.Ino == 0 || anchor.hostStat.Ino == 0 || sameNetns(anchor.ownStat, anchor.hostStat) {
		return nil, errors.New("agent namespace must differ from host PID1 namespace")
	}
	return anchor, nil
}

func anchorStats() (unix.Stat_t, unix.Stat_t, error) {
	a := verifiedNamespaces.Load()
	if a == nil || a.ownFD == nil || a.hostFD == nil {
		return unix.Stat_t{}, unix.Stat_t{}, errors.New("verified network namespace bootstrap required")
	}
	var own, host unix.Stat_t
	if err := unix.Fstat(int(a.ownFD.Fd()), &own); err != nil {
		return own, host, err
	}
	if err := unix.Fstat(int(a.hostFD.Fd()), &host); err != nil {
		return own, host, err
	}
	if !sameNetns(own, a.ownStat) || !sameNetns(host, a.hostStat) || sameNetns(own, host) {
		return own, host, errors.New("verified agent or host network namespace anchor changed")
	}
	return own, host, nil
}

func checkThreadOwn() error {
	own, _, err := anchorStats()
	if err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &current); err != nil {
		return err
	}
	if !sameNetns(current, own) {
		return errors.New("agent thread not in verified own network namespace")
	}
	return nil
}

// Pinned own and host FDs are intentionally retained for the process lifetime.
