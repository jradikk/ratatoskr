//go:build linux

package openvpn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	Interface = "upstream0"
	// Gateway contract: this mark/mask selects table 100 even when the main
	// default stays on eth0. The gateway keeps the route during unhealthy periods
	// and gates FORWARD only, permitting this locally originated recovery probe.
	ProbeMark         = 0x00100000
	ProbeMarkMask     = 0x00f00000
	ProbeRoutingTable = 100
)

// EnsureTUN implements ADR-0007 without changing permissions on an existing
// hostPath device. Device cgroup access is separately checked by opening it.
func EnsureTUN() error {
	const path = "/dev/net/tun"
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll("/dev/net", 0755); err != nil {
			return errors.New("cannot create TUN directory")
		}
		if err = syscall.Mknod(path, syscall.S_IFCHR|0600, int(10<<8|200)); err != nil && !errors.Is(err, syscall.EEXIST) {
			return errors.New("cannot create TUN device; check CAP_MKNOD or tunDevice hostPath")
		}
		st, err = os.Stat(path)
	}
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return errors.New("TUN path is not a character device")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Rdev != uint64(10<<8|200) {
		return errors.New("TUN device has incorrect device number")
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return errors.New("TUN device access denied; check runtime device cgroup or tunDevice hostPath")
	}
	return f.Close()
}

type commandProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *commandProcess) Done() <-chan struct{} { return p.done }
func (p *commandProcess) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return nil
	default:
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		// Bound the reap wait too; a stuck child must block any replacement process.
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-p.done:
			return nil
		case <-timer.C:
			return errors.New("child reap timeout")
		}
	}
}

// CommandStarter loads only the specified mounted configuration, never logs it,
// and writes the sanitized copy to a private temporary runtime file, not the
// repository. Its directory must be backed by ephemeral storage in production.
func CommandStarter(binary, secretDir, runtimeDir string) Starter {
	return func(ctx context.Context) (Process, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !filepath.IsAbs(secretDir) || !filepath.IsAbs(runtimeDir) {
			return nil, ConfigError()
		}
		// Validate the configuration file itself before reading it, too.
		if err := ValidateFiles([]byte("ca client.ovpn\n"), secretDir); err != nil {
			return nil, ConfigError()
		}
		f, err := os.Open(filepath.Join(secretDir, "client.ovpn"))
		if err != nil {
			return nil, ConfigError()
		}
		defer f.Close()
		auth, err := os.Stat(filepath.Join(secretDir, "auth.txt"))
		hasAuth := err == nil && auth.Mode().IsRegular()
		if err == nil && !hasAuth {
			return nil, ConfigError()
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, ConfigError()
		}
		config, err := Sanitize(f, hasAuth)
		if err != nil {
			return nil, ConfigError()
		}
		if err = ValidateFiles(config, secretDir); err != nil {
			return nil, ConfigError()
		}
		tmp, err := os.CreateTemp(runtimeDir, "openvpn-*.conf")
		if err != nil {
			return nil, errors.New("cannot create private runtime config")
		}
		cleanup := func() { _ = os.Remove(tmp.Name()) }
		if _, err = tmp.Write(config); err != nil {
			tmp.Close()
			cleanup()
			return nil, errors.New("cannot write runtime config")
		}
		if err = tmp.Close(); err != nil {
			cleanup()
			return nil, errors.New("cannot close runtime config")
		}
		cmd := exec.Command(binary, Arguments(tmp.Name())...)
		cmd.Dir = secretDir
		cmd.Stdin = nil
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		// Do not inherit unrelated secrets or provider-controlled environment.
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err = cmd.Start(); err != nil {
			cleanup()
			return nil, errors.New("cannot start OpenVPN")
		}
		p := &commandProcess{cmd: cmd, done: make(chan struct{})}
		go func() { _ = cmd.Wait(); cleanup(); close(p.done) }()
		return p, nil
	}
}

// NewHTTPProbe marks every TCP connection for table 100 and binds it to
// upstream0. Redirects are refused. It never uses environment proxies, HTTP
// keepalives or pod DNS: the URL must contain a literal IPv4 address. A hostname
// is deliberately not resolved through eth0. HTTPS uses normal certificate
// verification, so a literal address endpoint needs an IP SAN certificate.
func NewHTTPProbe(endpoint string) (Probe, error) {
	return newHTTPProbe(endpoint, net.InterfaceByName, nil)
}

func socketControl(raw syscall.RawConn, bind, mark func(int) error) error {
	var sockErr error
	err := raw.Control(func(fd uintptr) {
		sockErr = bind(int(fd))
		if sockErr == nil {
			sockErr = mark(int(fd))
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}

// Test dependencies avoid real sockets and external networks.
func newHTTPProbe(endpoint string, lookup func(string) (*net.Interface, error), roundTripper http.RoundTripper) (Probe, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
		return nil, errors.New("invalid probe URL")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return nil, errors.New("probe URL requires a unicast IPv4 literal")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		return socketControl(raw,
			func(fd int) error {
				return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, Interface)
			},
			func(fd int) error { return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, ProbeMark) })
	}}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, ResponseHeaderTimeout: 5 * time.Second}
	if roundTripper == nil {
		roundTripper = transport
	}
	client := &http.Client{Transport: roundTripper, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirects forbidden") }}
	return func(ctx context.Context) (ProbeResult, error) {
		iface, err := lookup(Interface)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return ProbeResult{}, errors.New("tunnel interface unavailable")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return ProbeResult{}, errors.New("probe request failed")
		}
		resp, err := client.Do(req)
		if err != nil {
			return ProbeResult{}, errors.New("tunnel probe failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ProbeResult{}, errors.New("probe status rejected")
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 65))
		exit, parseErr := netip.ParseAddr(strings.TrimSpace(string(b)))
		if err != nil || len(b) > 64 || parseErr != nil || !exit.Is4() || exit.IsUnspecified() || exit.IsLoopback() || exit.IsMulticast() {
			return ProbeResult{}, errors.New("invalid exit IP response")
		}
		return ProbeResult{exit.String(), iface.MTU}, nil
	}, nil
}
