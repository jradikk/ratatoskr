//go:build linux

package agent

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPinnedPIDLivenessWithoutNetnsEntry(t *testing.T) {
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
