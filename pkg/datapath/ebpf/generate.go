//go:build linux

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -no-strip client ../../../bpf/client.c -- -O1 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu
