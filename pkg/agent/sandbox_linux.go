//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
			return nil, err
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
	for _, ns := range details.RuntimeSpec.Linux.Namespaces {
		if ns.Type == "network" && ns.Path != "" {
			return openContainedNetns(ns.Path)
		}
	}
	if details.PID <= 1 {
		return nil, errors.New("sandbox PID unavailable")
	}
	// CRI metadata is authoritative for UID; the process path is opened without
	// following any intermediate /proc symlinks and never accepted as host netns.
	// A PID alone is not a sandbox identity: enforce its cgroup membership,
	// including systemd's underscore-escaped form, to reject PID recycling.
	cgroup, err := os.ReadFile("/proc/" + strconv.Itoa(details.PID) + "/cgroup")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(cgroup), uid) && !strings.Contains(string(cgroup), strings.ReplaceAll(uid, "-", "_")) {
		return nil, errors.New("sandbox PID cgroup does not match Pod UID")
	}
	path := "/proc/" + strconv.Itoa(details.PID) + "/ns/net"
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := rejectHost(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
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
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := rejectHost(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func rejectHost(f *os.File) error {
	var target, host unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &target); err != nil {
		return err
	}
	if err := unix.Stat("/proc/self/ns/net", &host); err != nil {
		return err
	}
	if target.Dev == host.Dev && target.Ino == host.Ino {
		return errors.New("refusing host network namespace")
	}
	if target.Ino == 0 {
		return errors.New("invalid network namespace")
	}
	return nil
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
