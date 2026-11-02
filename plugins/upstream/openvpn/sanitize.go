// Package openvpn implements the shared-network-namespace upstream contract.
package openvpn

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxConfigSize = 1 << 20

// Errors deliberately omit input, filenames and parser tokens: configurations
// can contain credentials even outside inline blocks.
var ErrConfig = errors.New("unsafe or unsupported OpenVPN configuration")

// A positive allowlist prevents future OpenVPN options from implicitly gaining
// access to scripts, files, process controls or the shared routing namespace.
var allowed = map[string]bool{}

func init() {
	for _, name := range strings.Fields(`client tls-client remote proto port rport lport nobind
 resolv-retry connect-retry connect-retry-max connect-timeout server-poll-timeout
 remote-random remote-random-hostname float persist-key persist-tun
 ping ping-restart ping-exit keepalive inactive explicit-exit-notify
 cipher data-ciphers data-ciphers-fallback auth auth-nocache auth-retry
 remote-cert-tls remote-cert-ku remote-cert-eku verify-x509-name peer-fingerprint
 tls-version-min tls-version-max tls-cipher tls-ciphersuites reneg-sec reneg-bytes
 reneg-pkts hand-window tran-window key-direction tun-mtu link-mtu mssfix fragment
 sndbuf rcvbuf fast-io tcp-nodelay topology ifconfig-nowarn
 mute-replay-warnings replay-window single-session tls-timeout
 ca cert key tls-auth tls-crypt tls-crypt-v2 extra-certs dh crl-verify auth-user-pass`) {
		allowed[name] = true
	}
}

var inline = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true, "extra-certs": true, "dh": true}
var files = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true, "extra-certs": true, "dh": true, "crl-verify": true}

func stripped(name string) bool {
	switch name {
	case "redirect-gateway", "redirect-private", "dhcp-option", "up", "down", "route-up", "route-pre-down", "ipchange", "script-security", "dev", "dev-type", "dev-node", "daemon", "syslog", "verb", "mute", "status", "status-version", "plugin", "route-nopull", "route-noexec", "pull-filter", "pull", "disable-dco":
		return true
	}
	return strings.HasPrefix(name, "log") || strings.HasPrefix(name, "management") || strings.HasPrefix(name, "route")
}

// Sanitize parses OpenVPN's quoting, escapes and line comments. It retains
// approved TLS inline blocks verbatim, strips namespace/process controls and
// rejects everything outside an explicit transport/TLS allowlist. auth-user-pass
// is emitted only once and always points at auth.txt (never its supplied path).
// File existence and symlink containment are checked separately by ValidateFiles.
func Sanitize(r io.Reader, hasAuth bool) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxConfigSize+1))
	if err != nil || len(b) > MaxConfigSize || strings.ContainsRune(string(b), '\x00') {
		return nil, ErrConfig
	}
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 4096), MaxConfigSize+1)
	block := ""
	authWritten := false
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if block != "" {
			if strings.TrimSpace(line) == "</"+block+">" {
				out.WriteString("</" + block + ">\n")
				block = ""
				continue
			}
			// No nested blocks; never interpret inline data as options.
			if strings.HasPrefix(strings.TrimSpace(line), "<") {
				return nil, ErrConfig
			}
			out.WriteString(line + "\n")
			continue
		}
		args, e := tokens(line)
		if e != nil {
			return nil, ErrConfig
		}
		if len(args) == 0 {
			continue
		}
		name := strings.TrimPrefix(args[0], "--")
		if strings.HasPrefix(name, "<") {
			if len(args) != 1 || !strings.HasSuffix(name, ">") {
				return nil, ErrConfig
			}
			tag := strings.TrimSuffix(strings.TrimPrefix(name, "<"), ">")
			if !inline[tag] {
				return nil, ErrConfig
			}
			block = tag
			out.WriteString("<" + tag + ">\n")
			continue
		}
		if stripped(name) {
			continue
		}
		if !allowed[name] {
			return nil, ErrConfig
		}
		if name == "auth-user-pass" {
			if !hasAuth || len(args) > 2 {
				return nil, ErrConfig
			}
			if !authWritten {
				out.WriteString("auth-user-pass auth.txt\n")
				authWritten = true
			}
			continue
		}
		if files[name] {
			if len(args) < 2 || len(args) > 3 || (len(args) == 3 && name != "tls-auth") {
				return nil, ErrConfig
			}
			if args[1] != "[inline]" && (name != "dh" || args[1] != "none") && !safeRelative(args[1]) {
				return nil, ErrConfig
			}
			if len(args) == 3 && args[2] != "0" && args[2] != "1" {
				return nil, ErrConfig
			}
		}
		out.WriteString(name)
		for _, arg := range args[1:] {
			out.WriteByte(' ')
			out.WriteString(quote(arg))
		}
		out.WriteByte('\n')
	}
	if scanner.Err() != nil || block != "" {
		return nil, ErrConfig
	}
	if hasAuth && !authWritten {
		out.WriteString("auth-user-pass auth.txt\n")
	}
	return []byte(out.String()), nil
}

// tokens mirrors the manual's single/double quotes, backslash escapes, and
// comments beginning at an unquoted token boundary. Reject multiline escapes.
func tokens(line string) ([]string, error) {
	var result []string
	var word strings.Builder
	var quote byte
	active := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && quote != '\'' {
			i++
			if i == len(line) {
				return nil, ErrConfig
			}
			if line[i] != '\\' && line[i] != '"' && line[i] != ' ' && line[i] != '\t' {
				return nil, ErrConfig
			}
			word.WriteByte(line[i])
			active = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			active = true
			continue
		}
		if c == ' ' || c == '\t' {
			if active {
				result = append(result, word.String())
				word.Reset()
				active = false
			}
			continue
		}
		if (c == '#' || c == ';') && !active {
			break
		}
		if c < ' ' {
			return nil, ErrConfig
		}
		word.WriteByte(c)
		active = true
	}
	if quote != 0 {
		return nil, ErrConfig
	}
	if active {
		result = append(result, word.String())
	}
	return result, nil
}
func quote(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
func safeRelative(p string) bool {
	if p == "" || filepath.IsAbs(p) || strings.ContainsAny(p, `\:`) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "" {
			return false
		}
	}
	return filepath.Clean(p) != "."
}

// ValidateFiles permits Kubernetes projected-secret symlinks only when their
// resolved target remains inside root. The mount must be immutable/read-only
// for the lifetime of a process; validate again before every restart.
func ValidateFiles(config []byte, root string) error {
	absolute, e := filepath.Abs(root)
	if e != nil {
		return ErrConfig
	}
	resolved, e := filepath.EvalSymlinks(absolute)
	if e != nil {
		return ErrConfig
	}
	scanner := bufio.NewScanner(strings.NewReader(string(config)))
	scanner.Buffer(make([]byte, 4096), MaxConfigSize+1)
	block := ""
	for scanner.Scan() {
		line := scanner.Text()
		if block != "" {
			if line == "</"+block+">" {
				block = ""
			}
			continue
		}
		args, e := tokens(line)
		if e != nil {
			return ErrConfig
		}
		if len(args) == 0 {
			continue
		}
		if strings.HasPrefix(args[0], "<") {
			block = strings.Trim(args[0], "<>")
			continue
		}
		if !files[args[0]] && args[0] != "auth-user-pass" {
			continue
		}
		if len(args) < 2 {
			return ErrConfig
		}
		p := args[1]
		if p == "[inline]" || (args[0] == "dh" && p == "none") {
			continue
		}
		if !safeRelative(p) {
			return ErrConfig
		}
		target, e := filepath.EvalSymlinks(filepath.Join(resolved, p))
		if e != nil {
			return ErrConfig
		}
		rel, e := filepath.Rel(resolved, target)
		if e != nil || !safeRelative(rel) {
			return ErrConfig
		}
		st, e := os.Stat(target)
		if e != nil || !st.Mode().IsRegular() {
			return ErrConfig
		}
	}
	if scanner.Err() != nil {
		return ErrConfig
	}
	return nil
}

// Arguments are appended after the sanitized configuration. Provider options
// cannot override any of these controls. OpenVPN output is discarded entirely.
func Arguments(configPath string) []string {
	return []string{"--config", configPath, "--dev", "upstream0", "--dev-type", "tun", "--route-nopull", "--route-noexec", "--pull-filter", "ignore", "redirect-gateway", "--pull-filter", "ignore", "dhcp-option", "--script-security", "1", "--disable-dco", "--auth-nocache", "--verb", "0"}
}

// ConfigError can be used by callers without disclosing parser input.
func ConfigError() error { return ErrConfig }
