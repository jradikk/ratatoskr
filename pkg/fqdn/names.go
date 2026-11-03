// Package fqdn provides per-workload DNS-derived IPv4 policy rules with a
// synchronous application barrier before selected DNS answers are released.
package fqdn

import (
	"errors"
	"net/netip"
	"strings"
)

var ErrInvalid = errors.New("invalid domain routing configuration or DNS response")
var ErrCapacity = errors.New("domain routing capacity exhausted")
var ErrApply = errors.New("domain routing application failed")

// NormalizeName accepts ASCII hostname labels (including punycode), canonicalizes
// case and one optional root dot, and refuses IP literals, escapes and wildcards.
func NormalizeName(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if len(name) == 0 || len(name) > 253 {
		return "", ErrInvalid
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", ErrInvalid
			}
		}
	}
	return name, nil
}

// MatchName is an exact, case-insensitive hostname comparison. Invalid inputs
// never match. MatchPattern additionally accepts a leading *. label.
func MatchName(name, exact string) bool {
	a, e := NormalizeName(name)
	b, f := NormalizeName(exact)
	return e == nil && f == nil && a == b
}
func MatchPattern(name, pattern string) bool {
	a, e := NormalizeName(name)
	if e != nil {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix, f := NormalizeName(strings.TrimPrefix(pattern, "*."))
		return f == nil && strings.Contains(suffix, ".") && a != suffix && strings.HasSuffix(a, "."+suffix)
	}
	return MatchName(a, pattern)
}
