package openvpn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeDeterministic(t *testing.T) {
	input := `# Entirely synthetic; these are not certificates or credentials.
client
remote 'vpn.example.invalid' 1194 udp ; provider comment
ca "assets/ca file.pem"
tls-auth assets/ta.key 1
remote-cert-tls server
<ca>
SYNTHETIC_CA_PLACEHOLDER
</ca>
<cert>
SYNTHETIC_CERT_PLACEHOLDER
</cert>
<key>
SYNTHETIC_KEY_PLACEHOLDER
</key>
<tls-auth>
SYNTHETIC_TLS_AUTH_PLACEHOLDER
</tls-auth>
redirect-gateway def1
redirect-private
dhcp-option DNS 192.0.2.53
up /never/run
route-up /never/run
route-pre-down /never/run
down /never/run
ipchange /never/run
script-security 3
plugin /never/load
--dev provider0
dev-type tap
dev-node /never/device
daemon
log-append /never/log
management 127.0.0.1 9000
management-client-auth
route 0.0.0.0 0.0.0.0
route-ipv6 ::/0
pull-filter accept route
verb 9
status /never/status
auth-user-pass /never/read
auth-user-pass /never/read-again
`
	want := "client\nremote \"vpn.example.invalid\" \"1194\" \"udp\"\nca \"assets/ca file.pem\"\ntls-auth \"assets/ta.key\" \"1\"\nremote-cert-tls \"server\"\n<ca>\nSYNTHETIC_CA_PLACEHOLDER\n</ca>\n<cert>\nSYNTHETIC_CERT_PLACEHOLDER\n</cert>\n<key>\nSYNTHETIC_KEY_PLACEHOLDER\n</key>\n<tls-auth>\nSYNTHETIC_TLS_AUTH_PLACEHOLDER\n</tls-auth>\nauth-user-pass auth.txt\n"
	for i := 0; i < 20; i++ {
		got, err := Sanitize(strings.NewReader(input), true)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("synthetic sanitized output mismatch: %q", got)
		}
	}
}
func TestSanitizeRejectsUnsafeInput(t *testing.T) {
	cases := []string{
		"config other.ovpn", "cd assets", "chroot assets", "setenv opt plugin evil", "setenv-safe TOKEN placeholder",
		"engine provider", "pkcs11-providers evil", "tls-verify evil", "tls-crypt-v2-verify evil",
		"auth-user-pass-verify evil via-env", "askpass assets/pass", "writepid assets/pid", "user nobody", "group nobody",
		"iproute evil", "ifconfig-noexec", "ifconfig 192.0.2.1 0.0.0.0", "ifconfig-ipv6 2001:db8::1/0 2001:db8::2", "server 10.0.0.0 255.255.255.0", "mode server", "unknown-future-option",
		"ca ../outside", "ca assets/../outside", "cert /absolute", `key C:\absolute`, `ca "assets\\outside"`,
		"ca .", "ca a//b", "ca", "ca file extra", "crl-verify assets/crl dir", "tls-auth assets/key 2",
		"auth-user-pass", "<auth-user-pass>\nSYNTHETIC\n</auth-user-pass>",
		"<ca>\nSYNTHETIC", "<ca>\n<key>\n</key>\n</ca>", "<connection>\nremote example.invalid\n</connection>",
		"</ca>", "<ca> extra", "remote \"unclosed", "remote dangling\\", "remote invalid\x00",
	}
	for _, input := range cases {
		// Never include input in errors; case indices suffice for test diagnosis.
		t.Run(strings.ReplaceAll(strings.Fields(input)[0], "/", "_"), func(t *testing.T) {
			got, err := Sanitize(strings.NewReader(input), false)
			if !errors.Is(err, ErrConfig) || got != nil {
				t.Fatal("expected generic rejection")
			}
			if err.Error() != ErrConfig.Error() {
				t.Fatal("error disclosed parser input")
			}
		})
	}
	_, err := Sanitize(bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxConfigSize+1)), false)
	if !errors.Is(err, ErrConfig) {
		t.Fatal("oversized input accepted")
	}
}
func TestSanitizeInlineVariantsAndEscapes(t *testing.T) {
	input := "ca [inline]\n<ca>\nSYNTHETIC\n</ca>\n<tls-crypt>\nSYNTHETIC\n</tls-crypt>\n<tls-crypt-v2>\nSYNTHETIC\n</tls-crypt-v2>\nremote \"vpn#example.invalid\"\nverify-x509-name \"CN=quoted\\\"name\" name\n"
	got, err := Sanitize(strings.NewReader(input), false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Sanitize(bytes.NewReader(got), false)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatal("sanitizer not idempotent")
	}
	got, err = Sanitize(strings.NewReader("client\r\n; comment\r\n"), true)
	if err != nil || string(got) != "client\nauth-user-pass auth.txt\n" {
		t.Fatal("optional auth rewrite failed")
	}
}
func TestValidateFilesAndProjectedSymlinks(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "..synthetic")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "ca.pem"), []byte("SYNTHETIC"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..synthetic/ca.pem", filepath.Join(root, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFiles([]byte("ca ca.pem\n<key>\nSYNTHETIC\n</key>\n"), root); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("SYNTHETIC"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.pem")); err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{"ca escape.pem\n", "ca missing\n", "ca ../outside\n", "ca\n", "ca /outside\n", "ca ..synthetic\n"} {
		if !errors.Is(ValidateFiles([]byte(config), root), ErrConfig) {
			t.Fatal("unsafe file reference accepted")
		}
	}
}
func TestForcedArguments(t *testing.T) {
	args := Arguments("/run/synthetic.conf")
	want := []string{"--config", "/run/synthetic.conf", "--dev", "upstream0", "--dev-type", "tun", "--route-nopull", "--route-noexec", "--pull-filter", "ignore", "redirect-gateway", "--pull-filter", "ignore", "dhcp-option", "--script-security", "1", "--disable-dco", "--auth-nocache", "--verb", "0"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatal("forced argument contract changed")
	}
}
