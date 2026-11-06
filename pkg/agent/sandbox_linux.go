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
type sandboxProof struct {
	id, namespace, name, uid, podIP string
	pid                             int
	path                            string
	inode                           unix.Stat_t
	pidfd                           int
}

func sandboxInfo(info map[string]string) (pid int, path string, err error) {
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
		return 0, "", fmt.Errorf("unsupported CRI verbose info: %w", err)
	}
	if details.PID <= 1 {
		return 0, "", errors.New("sandbox PID unavailable")
	}
	count := 0
	for _, ns := range details.RuntimeSpec.Linux.Namespaces {
		if ns.Type == "network" {
			count++
			path = ns.Path
		}
	}
	if count != 1 || path == "" {
		return 0, "", errors.New("exactly one CRI network namespace path required")
	}
	return details.PID, path, nil
}
func matchingSandbox(item *cri.PodSandbox, namespace, name, uid string) bool {
	md := item.GetMetadata()
	return md != nil && md.GetNamespace() == namespace && md.GetName() == name && md.GetUid() == uid && item.GetLabels()["io.kubernetes.pod.uid"] == uid && item.GetState() == cri.PodSandboxState_SANDBOX_READY
}
func matchingStatus(status *cri.PodSandboxStatus, id, namespace, name, uid, podIP string) bool {
	md := status.GetMetadata()
	return status != nil && status.GetId() == id && md != nil && md.GetNamespace() == namespace && md.GetName() == name && md.GetUid() == uid && status.GetLabels()["io.kubernetes.pod.uid"] == uid && status.GetState() == cri.PodSandboxState_SANDBOX_READY && status.GetNetwork().GetIp() == podIP
}

// Sandbox trusts CRI for sandbox ID -> nsfs path while independently checking
// its READY Pod identity and pinning a UID-owned live sandbox process.
func Sandbox(ctx context.Context, service cri.RuntimeServiceClient, namespace, name, uid, podIP string) (*os.File, sandboxProof, error) {
	proof := sandboxProof{pidfd: -1}
	if namespace == "" || name == "" || uid == "" || podIP == "" {
		return nil, proof, errors.New("incomplete pod identity")
	}
	list, err := service.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{Filter: &cri.PodSandboxFilter{LabelSelector: map[string]string{"io.kubernetes.pod.namespace": namespace, "io.kubernetes.pod.name": name, "io.kubernetes.pod.uid": uid}}})
	if err != nil {
		return nil, proof, fmt.Errorf("list CRI sandboxes: %w", err)
	}
	var item *cri.PodSandbox
	for _, candidate := range list.GetItems() {
		if !matchingSandbox(candidate, namespace, name, uid) {
			continue
		}
		if item != nil {
			return nil, proof, errors.New("multiple matching ready sandboxes")
		}
		item = candidate
	}
	if item == nil {
		return nil, proof, errors.New("matching ready sandbox unavailable")
	}
	resp, err := service.PodSandboxStatus(ctx, &cri.PodSandboxStatusRequest{PodSandboxId: item.GetId(), Verbose: true})
	if err != nil {
		return nil, proof, fmt.Errorf("CRI sandbox status: %w", err)
	}
	if !matchingStatus(resp.GetStatus(), item.GetId(), namespace, name, uid, podIP) {
		return nil, proof, errors.New("sandbox status identity mismatch")
	}
	pid, path, err := sandboxInfo(resp.GetInfo())
	if err != nil {
		return nil, proof, err
	}
	fd, err := retryInterrupted(func() (int, error) { return unix.PidfdOpen(pid, 0) })
	if err != nil {
		return nil, proof, fmt.Errorf("pin sandbox PID: %w", err)
	}
	proof.pidfd = fd
	fail := func(err error) (*os.File, sandboxProof, error) {
		unix.Close(fd)
		return nil, sandboxProof{pidfd: -1}, err
	}
	if err = checkPIDCgroup(fd, pid, uid); err != nil {
		return fail(fmt.Errorf("verify sandbox PID cgroup and liveness: %w", err))
	}
	f, err := openContainedNetns(path)
	if err != nil {
		return fail(fmt.Errorf("open verified sandbox netns: %w", err))
	}
	if err = statPinnedNamespace(int(f.Fd()), &proof.inode); err != nil {
		f.Close()
		return fail(fmt.Errorf("stat pinned CRI namespace FD: %w", err))
	}
	proof.id, proof.namespace, proof.name, proof.uid, proof.podIP, proof.pid, proof.path = item.GetId(), namespace, name, uid, podIP, pid, path
	if err = recheckSandbox(ctx, service, proof, f); err != nil {
		f.Close()
		return fail(fmt.Errorf("recheck pinned CRI sandbox proof: %w", err))
	}
	return f, proof, nil
}

// openSandboxNetns is retained as a safety-test entry point for CRI verbose
// payloads; production keeps the pidfd open across every recheck via Sandbox.
func openSandboxNetns(info map[string]string, uid string) (*os.File, error) {
	pid, path, err := sandboxInfo(info)
	if err != nil {
		return nil, err
	}
	fd, err := retryInterrupted(func() (int, error) { return unix.PidfdOpen(pid, 0) })
	if err != nil {
		return nil, fmt.Errorf("pin sandbox PID: %w", err)
	}
	defer unix.Close(fd)
	if err = checkPIDCgroup(fd, pid, uid); err != nil {
		return nil, err
	}
	f, err := openContainedNetns(path)
	if err != nil {
		return nil, err
	}
	if err = checkPIDCgroup(fd, pid, uid); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func checkPIDCgroup(fd, pid int, uid string) error {
	if err := checkPIDAlive(fd); err != nil {
		return fmt.Errorf("poll sandbox PID liveness: %w", err)
	}
	cgroup, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return fmt.Errorf("read sandbox PID cgroup: %w", err)
	}
	if !strings.Contains(string(cgroup), uid) && !strings.Contains(string(cgroup), strings.ReplaceAll(uid, "-", "_")) {
		return errors.New("sandbox PID cgroup does not match Pod UID")
	}
	if err := checkPIDAlive(fd); err != nil {
		return fmt.Errorf("poll sandbox PID liveness after cgroup read: %w", err)
	}
	return nil
}

// statPinnedNamespace reinitializes the result on every attempt; a failed
// fstat must never be compared against a previous successful inode.
func statPinnedNamespace(fd int, out *unix.Stat_t) error {
	return statPinnedNamespaceWith(fd, out, unix.Fstat)
}
func statPinnedNamespaceWith(fd int, out *unix.Stat_t, stat func(int, *unix.Stat_t) error) error {
	return retryInterruptedErr(func() error {
		*out = unix.Stat_t{}
		return stat(fd, out)
	})
}

func recheckSandbox(ctx context.Context, service cri.RuntimeServiceClient, p sandboxProof, f *os.File) error {
	return recheckSandboxWithStat(ctx, service, p, f, unix.Fstat)
}

func recheckSandboxWithStat(ctx context.Context, service cri.RuntimeServiceClient, p sandboxProof, f *os.File, stat func(int, *unix.Stat_t) error) error {
	if f == nil || p.id == "" || p.uid == "" || p.pid <= 1 || p.path == "" || p.pidfd < 0 {
		return errors.New("incomplete pinned CRI sandbox proof")
	}
	var current unix.Stat_t
	if err := statPinnedNamespaceWith(int(f.Fd()), &current, stat); err != nil {
		return fmt.Errorf("stat pinned CRI namespace FD: %w", err)
	}
	if !sameNetns(current, p.inode) {
		return errors.New("pinned CRI namespace FD changed")
	}
	if err := checkPIDCgroup(p.pidfd, p.pid, p.uid); err != nil {
		return fmt.Errorf("recheck sandbox PID cgroup and liveness: %w", err)
	}
	resp, err := service.PodSandboxStatus(ctx, &cri.PodSandboxStatusRequest{PodSandboxId: p.id, Verbose: true})
	if err != nil {
		return fmt.Errorf("recheck CRI sandbox status: %w", err)
	}
	if !matchingStatus(resp.GetStatus(), p.id, p.namespace, p.name, p.uid, p.podIP) {
		return errors.New("rechecked sandbox status identity changed")
	}
	pid, path, err := sandboxInfo(resp.GetInfo())
	if err != nil {
		return err
	}
	if pid != p.pid || path != p.path {
		return errors.New("rechecked sandbox PID or network namespace path changed")
	}
	list, err := service.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{Filter: &cri.PodSandboxFilter{LabelSelector: map[string]string{"io.kubernetes.pod.namespace": p.namespace, "io.kubernetes.pod.name": p.name, "io.kubernetes.pod.uid": p.uid}}})
	if err != nil {
		return fmt.Errorf("recheck CRI sandbox list: %w", err)
	}
	count := 0
	for _, item := range list.GetItems() {
		if !matchingSandbox(item, p.namespace, p.name, p.uid) {
			continue
		}
		count++
		if item.GetId() != p.id {
			return errors.New("rechecked CRI sandbox ID changed")
		}
	}
	if count != 1 {
		return errors.New("rechecked CRI ready sandbox missing or duplicated")
	}
	fresh, err := openContainedNetns(path)
	if err != nil {
		return fmt.Errorf("reopen confined CRI network namespace: %w", err)
	}
	defer fresh.Close()
	var observed unix.Stat_t
	if err = statPinnedNamespaceWith(int(fresh.Fd()), &observed, stat); err != nil {
		return fmt.Errorf("stat reopened CRI namespace FD: %w", err)
	}
	if !sameNetns(observed, p.inode) {
		return errors.New("rechecked CRI netns path no longer matches pinned FD")
	}
	if err := checkPIDCgroup(p.pidfd, p.pid, p.uid); err != nil {
		return fmt.Errorf("final sandbox PID cgroup and liveness recheck: %w", err)
	}
	return nil
}

// Polling a pidfd distinguishes a live sandbox process from a dead process
// whose namespace might remain pinned elsewhere. PID reuse cannot replace the
// process represented by this fd.
func checkPIDAlive(pidfd int) error {
	return checkPIDAliveWithPoll(pidfd, unix.Poll)
}

func checkPIDAliveWithPoll(pidfd int, poll func([]unix.PollFd, int) (int, error)) error {
	if pidfd < 0 || pidfd > math.MaxInt32 {
		return errors.New("invalid pidfd")
	}
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := retryInterrupted(func() (int, error) {
		fds[0].Revents = 0
		return poll(fds, 0)
	})
	if err != nil {
		return err
	}
	if n != 0 || fds[0].Revents != 0 {
		return errors.New("sandbox process exited")
	}
	return nil
}

// validateNetworkNamespaceFD enforces nsfs and the kernel namespace type. A
// regular file under the permitted directory must never become a setns target.
func validateNetworkNamespaceFD(f *os.File) error {
	if f == nil {
		return errors.New("network namespace FD unavailable")
	}
	var fs unix.Statfs_t
	if err := retryInterruptedErr(func() error {
		fs = unix.Statfs_t{}
		return unix.Fstatfs(int(f.Fd()), &fs)
	}); err != nil {
		return fmt.Errorf("stat CRI namespace filesystem: %w", err)
	}
	if fs.Type != int64(unix.NSFS_MAGIC) {
		return errors.New("CRI path does not name an nsfs namespace")
	}
	nstype, err := retryInterrupted(func() (int, error) { return unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE) })
	if err != nil {
		return fmt.Errorf("query CRI namespace type: %w", err)
	}
	if nstype != unix.CLONE_NEWNET {
		return errors.New("CRI path does not name a network namespace")
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
	root, err := retryInterrupted(func() (int, error) {
		return unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	})
	if err != nil {
		return nil, fmt.Errorf("open CRI namespace directory: %w", err)
	}
	defer unix.Close(root)
	fd, err := retryInterrupted(func() (int, error) {
		return unix.Openat2(root, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	})
	if err != nil {
		return nil, fmt.Errorf("open contained CRI network namespace: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := validateNetworkNamespaceFD(f); err != nil {
		f.Close()
		return nil, err
	}
	if err := rejectOwn(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("verify CRI namespace is not the agent namespace: %w", err)
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
			return errors.New("refusing agent network namespace")
		}
	}
	return nil
}

// rejectOwn is a distinct-agent namespace guard, not a host-inode guard.
// Host rejection relies on the READY CRI Pod UID/PodIP/cgroup binding and
// the selected target's exact eth0 IPv4 check before any mutation.
func rejectOwn(f *os.File) error {
	own, err := ownStat()
	if err != nil {
		return err
	}
	var target unix.Stat_t
	if err := statPinnedNamespace(int(f.Fd()), &target); err != nil {
		return fmt.Errorf("stat CRI namespace FD before own-namespace rejection: %w", err)
	}
	return rejectForbiddenNetns(target, own)
}

// switchThreadNamespace cannot assume that EINTR implies setns did not take
// effect. Inspect the locked thread after each interruption; retry only when
// it is still in the source namespace, and never execute caller code from an
// unexpected namespace. An exhausted restoration error is fatal to the caller.
func switchThreadNamespace(source, destination unix.Stat_t, fd int) error {
	return switchThreadNamespaceWith(source, destination, fd, unix.Setns, func() (unix.Stat_t, error) {
		var current unix.Stat_t
		err := retryInterruptedErr(func() error {
			current = unix.Stat_t{}
			return unix.Stat("/proc/thread-self/ns/net", &current)
		})
		return current, err
	})
}
func switchThreadNamespaceWith(source, destination unix.Stat_t, fd int, setns func(int, int) error, current func() (unix.Stat_t, error)) error {
	for attempt := 0; attempt < 16; attempt++ {
		err := setns(fd, unix.CLONE_NEWNET)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		observed, statErr := current()
		if statErr != nil {
			return fmt.Errorf("verify namespace after setns: %w", statErr)
		}
		if sameNetns(observed, destination) {
			return nil
		}
		if !sameNetns(observed, source) {
			return errors.New("thread left verified namespace during setns")
		}
		if err == nil {
			return errors.New("setns returned success without namespace transition")
		}
	}
	return unix.EINTR
}

// InNamespace pins the calling thread throughout backend creation and execution.
// Restoration happens before the caller updates Kubernetes metadata.
func InNamespace(target *os.File, fn func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// /proc/self/ns/net may refer to the process leader rather than this
	// locked OS thread. Restore the exact thread that performs setns.
	original, e := os.Open("/proc/thread-self/ns/net")
	if e != nil {
		return e
	}
	defer original.Close()
	if e = checkThreadOwn(); e != nil {
		return e
	}
	if e = rejectOwn(target); e != nil {
		return e
	}
	own, e := ownStat()
	if e != nil {
		return e
	}
	var destination unix.Stat_t
	if e = statPinnedNamespace(int(target.Fd()), &destination); e != nil {
		return fmt.Errorf("stat target namespace before setns: %w", e)
	}
	if e = switchThreadNamespace(own, destination, int(target.Fd())); e != nil {
		// Even a failed setns cannot be assumed to have left the thread in the
		// source namespace. Never return this OS thread to the Go scheduler if
		// a transition occurred but restoration cannot be established.
		if ownErr := checkThreadOwn(); ownErr != nil {
			panic(errors.Join(e, fmt.Errorf("failed entry left agent namespace: %w", ownErr)))
		}
		return fmt.Errorf("enter verified workload namespace: %w", e)
	}
	defer func() {
		if restore := switchThreadNamespace(destination, own, int(original.Fd())); restore != nil {
			panic(errors.Join(err, fmt.Errorf("restore agent namespace: %w", restore)))
		}
		if e := checkThreadOwn(); e != nil {
			panic(errors.Join(err, fmt.Errorf("restored thread differs from verified agent namespace: %w", e)))
		}
	}()
	return fn()
}
