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
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, proof, fmt.Errorf("pin sandbox PID: %w", err)
	}
	proof.pidfd = fd
	fail := func(err error) (*os.File, sandboxProof, error) {
		unix.Close(fd)
		return nil, sandboxProof{pidfd: -1}, err
	}
	if err = checkPIDCgroup(fd, pid, uid); err != nil {
		return fail(err)
	}
	f, err := openContainedNetns(path)
	if err != nil {
		return fail(fmt.Errorf("open verified sandbox netns: %w", err))
	}
	if err = unix.Fstat(int(f.Fd()), &proof.inode); err != nil {
		f.Close()
		return fail(err)
	}
	proof.id, proof.namespace, proof.name, proof.uid, proof.podIP, proof.pid, proof.path = item.GetId(), namespace, name, uid, podIP, pid, path
	if err = recheckSandbox(ctx, service, proof, f); err != nil {
		f.Close()
		return fail(err)
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
	fd, err := unix.PidfdOpen(pid, 0)
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
		return fmt.Errorf("sandbox PID exited: %w", err)
	}
	cgroup, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return fmt.Errorf("read sandbox PID cgroup: %w", err)
	}
	if !strings.Contains(string(cgroup), uid) && !strings.Contains(string(cgroup), strings.ReplaceAll(uid, "-", "_")) {
		return errors.New("sandbox PID cgroup does not match Pod UID")
	}
	return checkPIDAlive(fd)
}
func recheckSandbox(ctx context.Context, service cri.RuntimeServiceClient, p sandboxProof, f *os.File) error {
	if f == nil || p.id == "" || p.uid == "" || p.pid <= 1 || p.path == "" || p.pidfd < 0 {
		return errors.New("incomplete pinned CRI sandbox proof")
	}
	var current unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &current); err != nil {
		return err
	}
	if !sameNetns(current, p.inode) {
		return errors.New("pinned CRI namespace FD changed")
	}
	if err := checkPIDCgroup(p.pidfd, p.pid, p.uid); err != nil {
		return err
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
		return err
	}
	defer fresh.Close()
	var observed unix.Stat_t
	if err = unix.Fstat(int(fresh.Fd()), &observed); err != nil {
		return err
	}
	if !sameNetns(observed, p.inode) {
		return errors.New("rechecked CRI netns path no longer matches pinned FD")
	}
	return checkPIDCgroup(p.pidfd, p.pid, p.uid)
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

// validateNetworkNamespaceFD enforces nsfs and the kernel namespace type. A
// regular file under the permitted directory must never become a setns target.
func validateNetworkNamespaceFD(f *os.File) error {
	if f == nil {
		return errors.New("network namespace FD unavailable")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return fmt.Errorf("stat CRI namespace filesystem: %w", err)
	}
	if fs.Type != int64(unix.NSFS_MAGIC) {
		return errors.New("CRI path does not name an nsfs namespace")
	}
	nstype, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
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
	if err := validateNetworkNamespaceFD(f); err != nil {
		f.Close()
		return nil, err
	}
	if err := rejectOwn(f); err != nil {
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
	if err := unix.Fstat(int(f.Fd()), &target); err != nil {
		return err
	}
	return rejectForbiddenNetns(target, own)
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
	if e = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); e != nil {
		return e
	}
	defer func() {
		if restore := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restore != nil {
			panic(errors.Join(err, fmt.Errorf("restore agent namespace: %w", restore)))
		}
		if e := checkThreadOwn(); e != nil {
			panic(errors.Join(err, fmt.Errorf("restored thread differs from verified agent namespace: %w", e)))
		}
	}()
	return fn()
}
