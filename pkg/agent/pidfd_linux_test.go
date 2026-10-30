//go:build linux

package agent

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPinnedPIDExitAndCandidateGuards(t *testing.T) {
	if err := checkPIDAlive(-1); err == nil {
		t.Fatal("invalid pidfd accepted")
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd unavailable: %v", err)
	}
	defer unix.Close(fd)
	if err := checkPIDAlive(fd); err != nil {
		t.Fatalf("live pidfd rejected: %v", err)
	}
	if err := verifyPIDNetns(fd, nil); err == nil {
		t.Fatal("nil candidate accepted")
	}
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if err := verifyPIDNetns(fd, self); err == nil || !strings.Contains(err.Error(), "forbidden candidate") {
		t.Fatalf("self candidate should fail before setns: %v", err)
	}
	// The verifier rejection must not move the OS thread's namespace.
	if err := rejectHost(self); err == nil && !errors.Is(err, unix.EACCES) {
		t.Fatal("self netns unexpectedly accepted")
	}
}

func TestMissingCRIPathAndDeadPID(t *testing.T) {
	info := map[string]string{"info": `{"pid":999999999,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/var/run/netns/sandbox"}]}}}`}
	if f, err := openSandboxNetns(info, "uid"); err == nil {
		f.Close()
		t.Fatal("accepted dead sandbox PID")
	}
	info = map[string]string{"info": `{"pid":1,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/var/run/netns/../escape"}]}}}`}
	if f, err := openSandboxNetns(info, "uid"); err == nil {
		f.Close()
		t.Fatal("accepted host PID or traversal")
	}
}
