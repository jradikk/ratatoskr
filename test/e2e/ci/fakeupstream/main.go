// Command fakeupstream is a test-only upstream plugin and remote IP-echo server.
// It never contacts the Internet or needs credentials. Both sides use a plain
// IPIP tunnel; client-to-gateway traffic still uses the production GENEVE leg.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/skaldhall/ratatoskr/plugins/upstream/openvpn"
)

const remoteIP = "198.19.0.1"
const exitIP = "198.19.0.2"

func tunnel(local, remote netip.Addr, inner string) error {
	if !local.Is4() || !remote.Is4() || local == remote || remote.IsUnspecified() || remote.IsMulticast() {
		return errors.New("invalid test tunnel endpoints")
	}
	if l, err := netlink.LinkByName("upstream0"); err == nil {
		if err := netlink.LinkDel(l); err != nil {
			return err
		}
	} else {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return err
		}
	}
	v4 := func(a netip.Addr) net.IP { b := a.As4(); return net.IP(b[:]) }
	l := &netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: "upstream0", MTU: 1400}, Local: v4(local), Remote: v4(remote), Proto: unix.IPPROTO_IPIP, Ttl: 64}
	if err := netlink.LinkAdd(l); err != nil {
		return err
	}
	link, err := netlink.LinkByName("upstream0")
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(inner + "/30")
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}
func echo(w http.ResponseWriter, r *http.Request) {
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid peer", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		IP string `json:"ip"`
	}{addr})
}
func remoteMux(local netip.Addr) *http.ServeMux {
	mux := http.NewServeMux()
	var mu sync.Mutex
	mux.HandleFunc("/configure", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var cfg struct {
			GatewayIP netip.Addr `json:"gatewayIP"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			http.Error(w, "invalid config", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if err := tunnel(local, cfg.GatewayIP, remoteIP); err != nil {
			http.Error(w, "tunnel setup failed", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/echo", echo)
	mux.HandleFunc("/exit", func(w http.ResponseWriter, r *http.Request) {
		addr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid peer", http.StatusBadRequest)
			return
		}
		parsed, err := netip.ParseAddr(addr)
		if err != nil || !parsed.Is4() {
			http.Error(w, "invalid peer", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, parsed.String()) // #nosec G705 -- normalized IPv4 socket peer only, served as plain text, never HTML.
	})
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(bytes.Repeat([]byte("ratatoskr"), 512*1024))
	})
	return mux
}
func upstreamMux(healthy func() bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !healthy() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if !healthy() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ExitIP string `json:"exitIP"`
			MTU    int    `json:"mtu"`
		}{exitIP, 1400})
	})
	return mux
}
func run(role string, local, remote netip.Addr) error {
	addr := ":8080"
	var mux *http.ServeMux
	switch role {
	case "remote":
		mux = remoteMux(local)
	case "upstream":
		if !local.Is4() || !remote.Is4() {
			return errors.New("local and remote IPv4 endpoints required")
		}
		body, _ := json.Marshal(struct {
			GatewayIP netip.Addr `json:"gatewayIP"`
		}{local})
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
		var connected bool
		for i := 0; i < 30; i++ {
			resp, err := client.Post("http://"+remote.String()+":8080/configure", "application/json", bytes.NewReader(body))
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusNoContent {
					connected = true
					break
				}
			}
			time.Sleep(time.Second)
		}
		if !connected {
			return errors.New("remote test peer not ready")
		}
		if err := tunnel(local, remote, exitIP); err != nil {
			return err
		}
		probe, err := openvpn.NewHTTPProbe("http://" + remoteIP + ":8080/exit")
		if err != nil {
			return err
		}
		addr = "127.0.0.1:9901"
		mux = upstreamMux(func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result, err := probe(ctx)
			return err == nil && result.ExitIP == exitIP
		})
	default:
		return errors.New("role must be remote or upstream")
	}
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	return server.ListenAndServe()
}
func main() {
	role := flag.String("role", "remote", "remote or upstream")
	remote := flag.String("remote", "", "outer remote pod IP")
	local := flag.String("local", os.Getenv("POD_IP"), "outer local pod IP")
	flag.Parse()
	if *role == "down" || *role == "up" {
		link, err := netlink.LinkByName("upstream0")
		if err == nil {
			if *role == "down" {
				err = netlink.LinkSetDown(link)
			} else {
				err = netlink.LinkSetUp(link)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fake tunnel state change failed")
			os.Exit(1)
		}
		return
	}
	l, err := netip.ParseAddr(*local)
	if err != nil {
		fmt.Fprintln(os.Stderr, "POD_IP/local required")
		os.Exit(1)
	}
	r, _ := netip.ParseAddr(*remote)
	if err := run(*role, l, r); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("fake upstream failed", "error", err)
		os.Exit(1)
	}
}
