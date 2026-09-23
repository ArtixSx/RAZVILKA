package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// AnswerDetails retains the DNS lifetime and alias chain that an address-only
// lookup discards. AD is a statement made by the resolver, not local DNSSEC
// validation. No record here proves service access or authorizes a route.
type AnswerDetails struct {
	Addresses          []netip.Addr
	CNAMEChain         []string
	TTLSeconds         *uint32
	NegativeKind       string
	NegativeTTLSeconds *uint32
	ResolverReportedAD bool
}

// RFC 2181 section 8: a received TTL with the high bit set is zero.
func effectiveDNSTTL(value uint32) uint32 {
	if value > 0x7fffffff {
		return 0
	}
	return value
}

func exchangeCandidateDNSDetailed(parent context.Context, target dnsTarget, hostname string, recordType dnsmessage.Type) (AnswerDetails, error) {
	ctx, cancel := context.WithTimeout(parent, endpointProbeTimeout)
	defer cancel()
	query, err := buildDNSQueryFor(uint16(time.Now().UnixNano()), hostname, recordType)
	if err != nil {
		return AnswerDetails{}, err
	}
	response, err := target.probe(ctx, target.endpoint, query, target.trustedLocal)
	if err != nil {
		return AnswerDetails{}, err
	}
	return dnsAnswerDetails(query, response)
}

func dnsAnswerDetails(query, response []byte) (AnswerDetails, error) {
	addresses, ad, err := validateDNSAddressResponse(query, response)
	if err != nil && !errors.Is(err, errDNSNoAddress) && !errors.Is(err, errDNSNameError) {
		return AnswerDetails{}, err
	}
	// Integrity, question, family, terminal alias and size were checked by the
	// same validator used by the existing candidate path. This does no IO.
	var message dnsmessage.Message
	if message.Unpack(response) != nil {
		return AnswerDetails{}, errDNSAnswer
	}
	out := AnswerDetails{Addresses: addresses, ResolverReportedAD: ad}
	type alias struct {
		target string
		ttl    uint32
	}
	aliases := map[string]alias{}
	for _, rr := range message.Answers {
		if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
			owner := strings.ToLower(rr.Header.Name.String())
			value := alias{strings.ToLower(cname.CNAME.String()), effectiveDNSTTL(rr.Header.TTL)}
			if previous, exists := aliases[owner]; exists && previous.ttl < value.ttl {
				value.ttl = previous.ttl
			}
			aliases[owner] = value
		}
	}
	minimum := uint32(^uint32(0))
	terminal := strings.ToLower(message.Questions[0].Name.String())
	for step, ok := aliases[terminal]; ok; step, ok = aliases[terminal] {
		minimum = min(minimum, step.ttl)
		terminal = step.target
		out.CNAMEChain = append(out.CNAMEChain, strings.TrimSuffix(terminal, "."))
	}
	if err != nil {
		out.NegativeKind = "nodata"
		if errors.Is(err, errDNSNameError) {
			out.NegativeKind = "nxdomain"
		}
		out.NegativeTTLSeconds = negativeAnswerTTL(message.Authorities, terminal, minimum)
		return out, err
	}
	for _, rr := range message.Answers {
		if strings.ToLower(rr.Header.Name.String()) == terminal && rr.Header.Type == message.Questions[0].Type {
			minimum = min(minimum, effectiveDNSTTL(rr.Header.TTL))
		}
	}
	out.TTLSeconds = &minimum // zero is meaningful: do not reuse it later
	return out, nil
}

// RFC 2308 sections 3/5: only an authority SOA covering the final alias can
// supply a negative lifetime. Do not invent one for an empty reply/referral.
// The result describes this original-name lookup, so its alias TTL also bounds
// reuse. Ambiguous zones/classes fail closed for caching, without claiming the
// remote resolver is unreachable. AD remains only the resolver's statement.
func negativeAnswerTTL(authorities []dnsmessage.Resource, terminal string, aliasTTL uint32) *uint32 {
	var zone string
	var ttl *uint32
	for _, rr := range authorities {
		soa, ok := rr.Body.(*dnsmessage.SOAResource)
		if !ok {
			continue
		}
		owner := strings.ToLower(rr.Header.Name.String())
		if owner != "." && terminal != owner && !strings.HasSuffix(terminal, "."+owner) {
			continue
		}
		if rr.Header.Class != dnsmessage.ClassINET || zone != "" && zone != owner {
			return nil
		}
		zone = owner
		value := min(effectiveDNSTTL(rr.Header.TTL), effectiveDNSTTL(soa.MinTTL), aliasTTL)
		if ttl == nil || value < *ttl {
			ttl = &value
		}
	}
	return ttl
}
