//go:build linux

package agent

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type changingCRI struct {
	cri.RuntimeServiceClient
	id, ns, name, uid, ip      string
	pid                        int
	path                       string
	statusCalls, listCalls     int
	replaceStatus, replaceList bool
}

func (c *changingCRI) ListPodSandbox(_ context.Context, _ *cri.ListPodSandboxRequest, _ ...grpc.CallOption) (*cri.ListPodSandboxResponse, error) {
	c.listCalls++
	id := c.id
	if c.replaceList && c.listCalls > 1 {
		id = "new-sandbox"
	}
	md := &cri.PodSandboxMetadata{Namespace: c.ns, Name: c.name, Uid: c.uid}
	return &cri.ListPodSandboxResponse{Items: []*cri.PodSandbox{{Id: id, Metadata: md, Labels: map[string]string{"io.kubernetes.pod.uid": c.uid}, State: cri.PodSandboxState_SANDBOX_READY}}}, nil
}
func (c *changingCRI) PodSandboxStatus(_ context.Context, _ *cri.PodSandboxStatusRequest, _ ...grpc.CallOption) (*cri.PodSandboxStatusResponse, error) {
	c.statusCalls++
	pid, path := c.pid, c.path
	if c.replaceStatus && c.statusCalls > 1 {
		pid++
		path = "/var/run/netns/changed"
	}
	status := &cri.PodSandboxStatus{Id: c.id, Metadata: &cri.PodSandboxMetadata{Namespace: c.ns, Name: c.name, Uid: c.uid}, Labels: map[string]string{"io.kubernetes.pod.uid": c.uid}, State: cri.PodSandboxState_SANDBOX_READY, Network: &cri.PodSandboxNetworkStatus{Ip: c.ip}}
	return &cri.PodSandboxStatusResponse{Status: status, Info: map[string]string{"info": `{"pid":` + strconv.Itoa(pid) + `,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"` + path + `"}]}}}`}}, nil
}
func (c *changingCRI) proof(fd *os.File) sandboxProof {
	p := sandboxProof{id: c.id, namespace: c.ns, name: c.name, uid: c.uid, podIP: c.ip, pid: c.pid, path: c.path}
	_ = unix.Fstat(int(fd.Fd()), &p.inode)
	return p
}
func TestCRIAdversarialRechecksFailClosed(t *testing.T) {
	c := &changingCRI{id: "sandbox", ns: "ns", name: "pod", uid: "uid", ip: "10.2.0.3", pid: os.Getpid(), path: "/var/run/netns/sandbox"}
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	p := c.proof(self)
	p.pidfd, err = unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd unavailable: %v", err)
	}
	defer unix.Close(p.pidfd)
	if err := recheckSandbox(context.Background(), c, p, self); err == nil || !strings.Contains(err.Error(), "cgroup") {
		t.Fatalf("forged UID cgroup accepted: %v", err)
	}
	c.uid = ""
	p.uid = ""
	if err := recheckSandbox(context.Background(), c, p, self); err == nil {
		t.Fatal("empty UID accepted")
	}
	p.uid = "uid"
	c.uid = "uid"
	c.replaceStatus = true
	if err := recheckSandbox(context.Background(), c, p, self); err == nil || !strings.Contains(err.Error(), "PID") {
		t.Fatalf("replaced PID accepted: %v", err)
	}
	c.replaceStatus = false
	c.replaceList = true
	if err := recheckSandbox(context.Background(), c, p, self); err == nil {
		t.Fatal("replaced sandbox accepted")
	}
	p.inode.Ino++
	if err := recheckSandbox(context.Background(), c, p, self); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("changed pinned FD accepted: %v", err)
	}
}
func TestCRIStatusAndPathsRejectUntrustedInputs(t *testing.T) {
	md := &cri.PodSandboxMetadata{Namespace: "ns", Name: "pod", Uid: "uid"}
	status := &cri.PodSandboxStatus{Id: "sandbox", Metadata: md, Labels: map[string]string{"io.kubernetes.pod.uid": "uid"}, State: cri.PodSandboxState_SANDBOX_READY, Network: &cri.PodSandboxNetworkStatus{Ip: "10.2.0.3"}}
	if !matchingStatus(status, "sandbox", "ns", "pod", "uid", "10.2.0.3") {
		t.Fatal("valid status rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*cri.PodSandboxStatus)
	}{{"IP", func(s *cri.PodSandboxStatus) { s.Network.Ip = "10.2.0.4" }}, {"UID", func(s *cri.PodSandboxStatus) { s.Metadata.Uid = "other" }}, {"state", func(s *cri.PodSandboxStatus) { s.State = cri.PodSandboxState_SANDBOX_NOTREADY }}, {"ID", func(s *cri.PodSandboxStatus) { s.Id = "other" }}} {
		t.Run(tc.name, func(t *testing.T) {
			clone := &cri.PodSandboxStatus{Id: status.Id, Metadata: &cri.PodSandboxMetadata{Namespace: "ns", Name: "pod", Uid: "uid"}, Labels: map[string]string{"io.kubernetes.pod.uid": "uid"}, State: cri.PodSandboxState_SANDBOX_READY, Network: &cri.PodSandboxNetworkStatus{Ip: "10.2.0.3"}}
			tc.mutate(clone)
			if matchingStatus(clone, "sandbox", "ns", "pod", "uid", "10.2.0.3") {
				t.Fatal("mismatched CRI status accepted")
			}
		})
	}
	for _, raw := range []string{`{"pid":2,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/var/run/netns/a"},{"type":"network","path":"/var/run/netns/b"}]}}}`, `{"pid":2,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":""}]}}}`, `{"pid":0,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/var/run/netns/a"}]}}}`} {
		if _, _, err := sandboxInfo(map[string]string{"info": raw}); err == nil {
			t.Fatal("invalid CRI path accepted")
		}
	}
	if _, err := openContainedNetns("/var/run/netns/../escape"); err == nil {
		t.Fatal("traversal accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "fake-netns")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateNetworkNamespaceFD(file); err == nil || !strings.Contains(err.Error(), "nsfs") {
		t.Fatalf("regular file accepted as nsfs: %v", err)
	}
	if err := validateNetworkNamespaceFD(nil); err == nil {
		t.Fatal("nil FD accepted")
	}
}
