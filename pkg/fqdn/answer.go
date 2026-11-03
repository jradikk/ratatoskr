package fqdn

import (
	"net/netip"
	"time"

	mdns "github.com/miekg/dns"
)

type addressTTL struct {
	addr netip.Addr
	ttl  time.Duration
}
type cname struct {
	target string
	ttl    uint32
}

// learnable only traverses Answer records reachable from the exact question.
// Additional/Authority addresses are never routing authority. Mixed classes,
// loops, ambiguous aliases and malformed addresses fail the entire transaction.
func learnable(req, answer *mdns.Msg, maxRecords, maxChain int, maxTTL time.Duration) ([]addressTTL, error) {
	if !answer.Response || answer.Id != req.Id || answer.Opcode != req.Opcode || len(answer.Question) != 1 || answer.Question[0].Qtype != req.Question[0].Qtype || answer.Question[0].Qclass != req.Question[0].Qclass || !MatchName(answer.Question[0].Name, req.Question[0].Name) {
		return nil, ErrInvalid
	}
	if answer.Truncated || len(answer.Answer)+len(answer.Ns)+len(answer.Extra) > maxRecords {
		return nil, ErrInvalid
	}
	if answer.Rcode != mdns.RcodeSuccess {
		return nil, nil
	}
	aliases := map[string]cname{}
	records := map[string]map[netip.Addr]uint32{}
	for _, rr := range answer.Answer {
		if rr == nil || rr.Header().Class != mdns.ClassINET {
			return nil, ErrInvalid
		}
		owner, err := NormalizeName(rr.Header().Name)
		if err != nil {
			return nil, ErrInvalid
		}
		switch value := rr.(type) {
		case *mdns.CNAME:
			target, e := NormalizeName(value.Target)
			if e != nil {
				return nil, ErrInvalid
			}
			if old, ok := aliases[owner]; ok {
				if old.target != target {
					return nil, ErrInvalid
				}
				if old.ttl < value.Hdr.Ttl {
					value = &mdns.CNAME{Hdr: mdns.RR_Header{Ttl: old.ttl}, Target: value.Target}
				}
			}
			aliases[owner] = cname{target, value.Hdr.Ttl}
		case *mdns.A:
			addr, ok := netip.AddrFromSlice(value.A)
			addr = addr.Unmap()
			if !ok || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				return nil, ErrInvalid
			}
			if records[owner] == nil {
				records[owner] = map[netip.Addr]uint32{}
			}
			ttl, exists := records[owner][addr]
			if !exists || value.Hdr.Ttl < ttl {
				records[owner][addr] = value.Hdr.Ttl
			}
		}
	}
	name, _ := NormalizeName(req.Question[0].Name)
	seen := map[string]bool{}
	limiting := maxTTL
	for depth := 0; depth <= maxChain; depth++ {
		if seen[name] {
			return nil, ErrInvalid
		}
		seen[name] = true
		if alias, ok := aliases[name]; ok {
			if len(records[name]) > 0 || depth == maxChain {
				return nil, ErrInvalid
			}
			ttl := time.Duration(alias.ttl) * time.Second
			if ttl < limiting {
				limiting = ttl
			}
			name = alias.target
			continue
		}
		if depth > 0 && len(records[name]) == 0 {
			return nil, ErrInvalid
		}
		out := make([]addressTTL, 0, len(records[name]))
		for addr, seconds := range records[name] {
			ttl := time.Duration(seconds) * time.Second
			if limiting < ttl {
				ttl = limiting
			}
			if ttl <= 0 {
				return nil, ErrInvalid
			}
			out = append(out, addressTTL{addr, ttl})
		}
		return out, nil
	}
	return nil, ErrInvalid
}
