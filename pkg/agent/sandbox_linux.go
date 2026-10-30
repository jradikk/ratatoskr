//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Sandbox resolves only a READY CRI sandbox whose full Kubernetes identity matches.
func Sandbox(ctx context.Context, service cri.RuntimeServiceClient, namespace, name, uid, podIP string) (*os.File, error) {
	if namespace == "" || name == "" || uid == "" || podIP == "" {
		return nil, errors.New("incomplete pod identity")
	}
	list, err := service.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{Filter: &cri.PodSandboxFilter{LabelSelector: map[string]string{"io.kubernetes.pod.namespace": namespace, "io.kubernetes.pod.name": name, "io.kubernetes.pod.uid": uid}}})
	if err != nil {
		return nil, err
	}
	var found *os.File
	for _, item := range list.GetItems() {
		md := item.GetMetadata()
		if md == nil || md.GetNamespace() != namespace || md.GetName() != name || md.GetUid() != uid || item.GetLabels()["io.kubernetes.pod.uid"] != uid || item.GetState() != cri.PodSandboxState_SANDBOX_READY {
			continue
		}
		response, err := service.PodSandboxStatus(ctx, &cri.PodSandboxStatusRequest{PodSandboxId: item.GetId(), Verbose: true})
		if err != nil {
			if found != nil {
				found.Close()
			}
			return nil, err
		}
		status := response.GetStatus()
		if status == nil || status.GetId() != item.GetId() || status.GetMetadata() == nil || status.GetMetadata().GetNamespace() != namespace || status.GetMetadata().GetName() != name || status.GetMetadata().GetUid() != uid || status.GetLabels()["io.kubernetes.pod.uid"] != uid || status.GetState() != cri.PodSandboxState_SANDBOX_READY || status.GetNetwork().GetIp() != podIP {
			if found != nil {
				found.Close()
			}
			return nil, errors.New("sandbox status identity mismatch")
		}
		f, err := openSandboxNetns(response.GetInfo(), uid)
		if err != nil {
			if found != nil {
				found.Close()
			}
			return nil, fmt.Errorf("open verified sandbox netns: %w", err)
		}
		if found != nil {
			f.Close()
			found.Close()
			return nil, errors.New("multiple matching ready sandboxes")
		}
		found = f
	}
	if found == nil {
		return nil, errors.New("matching ready sandbox unavailable")
	}
	return found, nil
}

func openSandboxNetns(info map[string]string, uid string) (*os.File, error) {
	var details struct {
		PID         int `json:"pid"`
		RuntimeSpec struct {
			Linux struct {
				Namespaces []struct {
					Type string `json:"type"`
					Path string `json:"path"`
				} `json:"namespaces"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	}
	if err := json.Unmarshal([]byte(info["info"]), &details); err != nil {
		return nil, fmt.Errorf("unsupported CRI verbose info: %w", err)
	}
	if details.PID <= 1 {
		return nil, errors.New("sandbox PID unavailable; cannot corroborate reported netns path")
	}
	// Pin the reported sandbox process before reading its cgroup. The pidfd
	// prevents PID reuse between UID verification and namespace comparison.
	pidfd, err := unix.PidfdOpen(details.PID, 0)
	if err != nil {
		return nil, fmt.Errorf("pin sandbox PID: %w", err)
	}
	defer unix.Close(pidfd)
	// A PID alone is not a sandbox identity: require its cgroup to contain
	// the Kubernetes Pod UID (including systemd's underscore-escaped form).
	cgroup, err := os.ReadFile("/proc/" + strconv.Itoa(details.PID) + "/cgroup")
	if err != nil {
		return nil, fmt.Errorf("read sandbox PID cgroup: %w", err)
	}
	if !strings.Contains(string(cgroup), uid) && !strings.Contains(string(cgroup), strings.ReplaceAll(uid, "-", "_")) {
		return nil, errors.New("sandbox PID cgroup does not match Pod UID")
	}
	if err := checkPIDAlive(pidfd); err != nil {
		return nil, fmt.Errorf("sandbox PID exited during cgroup verification: %w", err)
	}
	// The CRI path is mandatory, confined by openat2, and never followed via
	// symlinks. Transient setns(pidfd) corroborates this pinned candidate even
	// when hidepid/Yama forbids opening /proc/<PID>/ns/net directly.
	var candidate *os.File
	for _, ns := range details.RuntimeSpec.Linux.Namespaces {
		if ns.Type != "network" {
			continue
		}
		if candidate != nil {
			candidate.Close()
			return nil, errors.New("multiple CRI network namespace paths")
		}
		candidate, err = openContainedNetns(ns.Path)
		if err != nil {
			return nil, fmt.Errorf("verify CRI-reported network namespace path: %w", err)
		}
	}
	if candidate == nil {
		return nil, errors.New("CRI network namespace path unavailable")
	}
	if err := verifyPIDNetns(pidfd, candidate); err != nil {
		candidate.Close()
		return nil, fmt.Errorf("corroborate CRI path with pinned sandbox PID: %w", err)
	}
	if err := checkPIDAlive(pidfd); err != nil {
		candidate.Close()
		return nil, fmt.Errorf("sandbox PID exited after namespace comparison: %w", err)
	}
	return candidate, nil
}

// Polling a pidfd distinguishes a live sandbox process from a dead process
// whose namespace might remain pinned elsewhere. PID reuse cannot replace the
// process represented by this fd.
func checkPIDAlive(pidfd int) error {
	if pidfd < 0 || pidfd > math.MaxInt32 {
		return errors.New("invalid pidfd")
	}
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return err
	}
	if n != 0 || fds[0].Revents != 0 {
		return errors.New("sandbox process exited")
	}
	return nil
}

// verifyPIDNetns compares the pinned pidfd's actual network namespace with
// the confined CRI netns fd on the current OS thread. The original thread
// namespace is restored even if comparison, stat or liveness checks fail.
func verifyPIDNetns(pidfd int, candidate *os.File) (err error) {
	if candidate == nil {
		return errors.New("candidate network namespace is required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return fmt.Errorf("save verifier thread namespace: %w", err)
	}
	defer original.Close()
	if err := rejectHost(candidate); err != nil {
		return fmt.Errorf("reject forbidden candidate namespace: %w", err)
	}
	var candidateStat, originalStat unix.Stat_t
	if err := unix.Fstat(int(candidate.Fd()), &candidateStat); err != nil {
		return fmt.Errorf("stat candidate namespace before setns: %w", err)
	}
	if err := unix.Fstat(int(original.Fd()), &originalStat); err != nil {
		return fmt.Errorf("stat original thread namespace before setns: %w", err)
	}
	if err := rejectForbiddenNetns(candidateStat, originalStat); err != nil {
		return fmt.Errorf("reject current thread namespace before setns: %w", err)
	}
	if err := checkPIDAlive(pidfd); err != nil {
		return fmt.Errorf("sandbox PID not live before namespace comparison: %w", err)
	}
	if err := unix.Setns(pidfd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter pinned sandbox PID namespace: %w", err)
	}
	defer func() {
		if restore := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restore != nil {
			panic(errors.Join(err, fmt.Errorf("restore verifier thread namespace: %w", restore)))
		}
	}()
	current, statErr := os.Open("/proc/thread-self/ns/net")
	if statErr != nil {
		return fmt.Errorf("open verifier thread namespace after setns: %w", statErr)
	}
	defer current.Close()
	var entered, reported unix.Stat_t
	if statErr = unix.Fstat(int(current.Fd()), &entered); statErr != nil {
		return fmt.Errorf("stat verifier thread namespace: %w", statErr)
	}
	if statErr = unix.Fstat(int(candidate.Fd()), &reported); statErr != nil {
		return fmt.Errorf("stat confined CRI namespace: %w", statErr)
	}
	if !sameNetns(entered, reported) {
		return errors.New("reported netns differs from pinned sandbox PID netns")
	}
	if err := checkPIDAlive(pidfd); err != nil {
		return fmt.Errorf("sandbox PID exited during namespace comparison: %w", err)
	}
	return nil
}

func openContainedNetns(path string) (*os.File, error) {
	const base = "/var/run/netns"
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, base+"/") {
		return nil, errors.New("netns path outside /var/run/netns")
	}
	rel := strings.TrimPrefix(path, base+"/")
	if rel == "" || strings.Contains(rel, "/") || rel == "." || rel == ".." {
		return nil, errors.New("netns path is not a direct child")
	}
	root, err := unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, fmt.Errorf("open contained CRI network namespace: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := rejectHost(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func sameNetns(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Ino != 0
}

func rejectForbiddenNetns(target unix.Stat_t, forbidden ...unix.Stat_t) error {
	if target.Ino == 0 {
		return errors.New("invalid network namespace")
	}
	for _, namespace := range forbidden {
		if sameNetns(target, namespace) {
			return errors.New("refusing agent or host network namespace")
		}
	}
	return nil
}

func rejectHost(f *os.File) error {
	var target unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &target); err != nil {
		return err
	}
	// hostPID exposes node PID1 even when this agent's own Pod has a distinct
	// network namespace. Both must be excluded before any setns attempt.
	var forbidden []unix.Stat_t
	for _, path := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		var namespace unix.Stat_t
		if err := unix.Stat(path, &namespace); err != nil {
			return fmt.Errorf("verify forbidden namespace %s: %w", path, err)
		}
		forbidden = append(forbidden, namespace)
	}
	return rejectForbiddenNetns(target, forbidden...)
}

// InNamespace pins the calling thread throughout backend creation and execution.
// Restoration happens before the caller updates Kubernetes metadata.
func InNamespace(target *os.File, fn func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, e := os.Open("/proc/self/ns/net")
	if e != nil {
		return e
	}
	defer original.Close()
	if e = rejectHost(target); e != nil {
		return e
	}
	if e = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); e != nil {
		return e
	}
	defer func() {
		if restore := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restore != nil {
			err = errors.Join(err, fmt.Errorf("restore host namespace: %w", restore))
			panic(err)
		}
	}()
	return fn()
}
