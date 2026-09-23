package dnscontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var ErrScopedDNS = errors.New("scoped DNS query not permitted")

// ClientDNSBinding is an exact client/domain selection, not a LAN-wide suffix
// rule. The transaction owner supplies already authorized bindings and a guard
// that fences changes to its network/configuration epoch. This primitive does
// not commit DNS settings, redirect port 53 or authorize a service route.
type ClientDNSBinding struct {
	Client    netip.Addr
	Domain    string
	ProfileID string
}

type scopedDNSKey struct {
	client netip.Addr
	host   string
}

type scopedDNSChoice struct {
	provider Provider
	target   dnsTarget
}

// ScopedDNSResolver has no disk cache and never falls back to another resolver.
// The same existing Manager, provider catalogue and strict HTTPS transport are
// used by the diagnostic and future transactional client paths.
type ScopedDNSResolver struct {
	manager *Manager
	choices map[scopedDNSKey]scopedDNSChoice
	guard   func(context.Context) error
	cache   scopedAnswerCache
}

func (m *Manager) NewScopedDNSResolver(bindings []ClientDNSBinding, guard func(context.Context) error) (*ScopedDNSResolver, error) {
	if len(bindings) == 0 || len(bindings) > 128 || guard == nil {
		return nil, ErrScopedDNS
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	r := &ScopedDNSResolver{manager: m, choices: make(map[scopedDNSKey]scopedDNSChoice), guard: guard}
	for _, binding := range bindings {
		if !binding.Client.IsValid() || binding.Client.Is4In6() || binding.Client.Zone() != "" || !binding.Client.IsGlobalUnicast() && !binding.Client.IsLoopback() {
			return nil, ErrScopedDNS
		}
		host, err := normalizeCandidateHostname(binding.Domain)
		if err != nil || host == "home.arpa" {
			return nil, ErrScopedDNS
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return nil, ErrScopedDNS
		}
		profile, ok := profileByID(binding.ProfileID)
		if !ok {
			return nil, ErrScopedDNS
		}
		provider, ok := providerByIDFor(profile.ProviderID, m.doc)
		if !ok || !provider.Configured || provider.Scope == "negative-control" || provider.TrustedLocal {
			return nil, ErrScopedDNS
		}
		var choice scopedDNSChoice
		for _, endpoint := range provider.Endpoints {
			if endpoint.Transport != "doh" {
				continue
			}
			if target, ok := endpointProbeTarget(endpoint, false); ok {
				choice = scopedDNSChoice{provider, target}
				break
			}
		}
		key := scopedDNSKey{binding.Client, host}
		if _, exists := r.choices[key]; exists || choice.target.detailedDoH == nil {
			return nil, ErrScopedDNS
		}
		r.choices[key] = choice
	}
	return r, nil
}

// Resolve forwards the original client flags, question and EDNS DO bit. It
// preserves authenticated DNS data rather than synthesizing A/AAAA records.
// Unknown types/options are explicitly refused by this first scoped executor.
func (r *ScopedDNSResolver) Resolve(ctx context.Context, client netip.Addr, query []byte) (_ []byte, resultErr error) {
	message, _, err := scopedDNSQuestion(query)
	if err != nil {
		return nil, err
	}
	key := scopedDNSKey{client, strings.ToLower(strings.TrimSuffix(message.Questions[0].Name.String(), "."))}
	choice, ok := r.choices[key]
	if !ok {
		return nil, ErrScopedDNS
	}
	if err := r.check(ctx, choice); err != nil {
		return nil, err
	}
	cacheKey, identity := scopedAnswerIdentity(key, message, query)
	ticket, started, cached := r.cache.begin(cacheKey, identity, message.ID)
	if cached != nil {
		if err := r.check(ctx, choice); err != nil {
			return nil, err
		}
		return cached, nil
	}
	// Record a failure without extending the previous answer's expiry/grace.
	var accepted bool
	defer func() {
		if !accepted {
			r.cache.fail(cacheKey, ticket, resultErr)
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, endpointProbeTimeout)
	defer cancel()
	response, err := choice.target.detailedDoH(bounded, choice.target.endpoint, query, false)
	if err != nil {
		return nil, err
	}
	if err = r.check(ctx, choice); err != nil {
		return nil, err
	}
	_, _, err = validateDNSAddressResponse(query, response.wire)
	negative := errors.Is(err, errDNSNoAddress) || errors.Is(err, errDNSNameError)
	if err != nil && !errors.Is(err, errDNSNoAddress) && !errors.Is(err, errDNSNameError) {
		return nil, err
	}
	var answer dnsmessage.Message
	if answer.Unpack(response.wire) != nil || answer.CheckingDisabled != message.CheckingDisabled || answer.RecursionDesired != message.RecursionDesired {
		return nil, errDNSAnswer
	}
	opt := 0
	for _, section := range [][]dnsmessage.Resource{answer.Answers, answer.Authorities, answer.Additionals} {
		for _, record := range section {
			switch body := record.Body.(type) {
			case *dnsmessage.AResource:
				if !publicDNSAddress(netip.AddrFrom4(body.A)) {
					return nil, errDNSAnswer
				}
			case *dnsmessage.AAAAResource:
				if !publicDNSAddress(netip.AddrFrom16(body.AAAA)) {
					return nil, errDNSAnswer
				}
			case *dnsmessage.OPTResource:
				opt++
				if opt > 1 || record.Header.Name.String() != "." || record.Header.TTL&0xffff7fff != 0 {
					return nil, errDNSAnswer // no hidden extended RCODE/version
				}
			}
		}
	}
	wire, err := ageDNSWire(response.wire, response.age, negative)
	if err != nil {
		return nil, err
	}
	// The client and ledger use the same capped lifetime. Header-only edits
	// preserve signed RDATA and never modify the EDNS flags.
	limit := scopedCacheTTL
	if negative {
		limit = scopedNegativeTTL
	}
	offsets, err := dnsWireTTLOffsets(wire)
	if err != nil {
		return nil, err
	}
	for _, offset := range offsets {
		ttl := binary.BigEndian.Uint32(wire[offset:])
		binary.BigEndian.PutUint32(wire[offset:], min(ttl, uint32(limit/time.Second)))
	}
	details, err := dnsAnswerDetails(query, wire)
	if err != nil && !scopedNegative(err) {
		return nil, err
	}
	if err = r.check(ctx, choice); err != nil {
		return nil, err
	}
	r.cache.accept(cacheKey, identity, ticket, started, wire, details)
	accepted = true
	elapsed := max(time.Duration(0), r.cache.clock().Sub(started))
	return ageDNSWire(wire, uint64((elapsed+time.Second-1)/time.Second), negative)
}

func (r *ScopedDNSResolver) check(ctx context.Context, choice scopedDNSChoice) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.guard(ctx); err != nil {
		r.cache.clear()
		return err
	}
	r.manager.mu.RLock()
	current, exists := providerByIDFor(choice.provider.ID, r.manager.doc)
	r.manager.mu.RUnlock()
	if !exists || !reflect.DeepEqual(current, choice.provider) {
		r.cache.clear()
		return ErrServiceDNSChanged
	}
	return nil
}

func scopedDNSQuestion(wire []byte) (dnsmessage.Message, int, error) {
	var message dnsmessage.Message
	if len(wire) < 12 || len(wire) > 4096 || wire[3]&0x40 != 0 || message.Unpack(wire) != nil {
		return message, 0, ErrScopedDNS
	}
	if message.Response || message.OpCode != 0 || message.Truncated || !message.RecursionDesired || message.RCode != 0 || len(message.Questions) != 1 || len(message.Answers) != 0 || len(message.Authorities) != 0 || len(message.Additionals) > 1 {
		return message, 0, ErrScopedDNS
	}
	q := message.Questions[0]
	if q.Class != dnsmessage.ClassINET || q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		return message, 0, ErrScopedDNS
	}
	size := 512
	for _, rr := range message.Additionals {
		body, ok := rr.Body.(*dnsmessage.OPTResource)
		if !ok || rr.Header.Name.String() != "." || rr.Header.TTL&0xffff7fff != 0 || len(body.Options) != 0 {
			return message, 0, ErrScopedDNS // no implicit ECS or unknown semantics
		}
		size = max(512, min(1232, int(rr.Header.Class)))
	}
	if _, err := dnsWireTTLOffsets(wire); err != nil {
		return message, 0, ErrScopedDNS
	}
	return message, size, nil
}

// Patch only RR header TTLs. Repacking unknown RDATA can corrupt compression
// pointers; altering OPT flags, SOA MINIMUM or RRSIG signed data changes meaning.
func ageDNSWire(wire []byte, age uint64, negative bool) ([]byte, error) {
	offsets, err := dnsWireTTLOffsets(wire)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), wire...)
	// Negative caching uses min(SOA TTL, SOA MINIMUM). Consume HTTP age
	// after that minimum, via the unsigned RR header only (RFC 2308/8484).
	// Keeping MINIMUM untouched is necessary for signed SOA RDATA.
	if negative {
		var message dnsmessage.Message
		if message.Unpack(wire) != nil {
			return nil, errDNSAnswer
		}
		index := 0
		for _, section := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
			for _, record := range section {
				if record.Header.Type == dnsmessage.TypeOPT {
					continue
				}
				if index >= len(offsets) {
					return nil, errDNSAnswer
				}
				if soa, ok := record.Body.(*dnsmessage.SOAResource); ok {
					binary.BigEndian.PutUint32(out[offsets[index]:], min(effectiveDNSTTL(record.Header.TTL), effectiveDNSTTL(soa.MinTTL)))
				}
				index++
			}
		}
	}
	for _, offset := range offsets {
		ttl := effectiveDNSTTL(binary.BigEndian.Uint32(out[offset:]))
		binary.BigEndian.PutUint32(out[offset:], *remainingDNSTTL(&ttl, age))
	}
	return out, nil
}

// The normal DNS parser validates names/RDATA first; this bounds the raw
// layout and rejects trailing bytes while locating headers without decoding
// compression targets a second time.
func dnsWireTTLOffsets(wire []byte) ([]int, error) {
	if len(wire) < 12 || len(wire) > 65535 {
		return nil, errDNSAnswer
	}
	pos := 12
	name := func() bool {
		for pos < len(wire) {
			n := int(wire[pos])
			pos++
			if n == 0 {
				return true
			}
			if n&0xc0 == 0xc0 {
				pos++
				return pos <= len(wire)
			}
			if n > 63 || pos+n > len(wire) {
				return false
			}
			pos += n
		}
		return false
	}
	for i := 0; i < int(binary.BigEndian.Uint16(wire[4:6])); i++ {
		if !name() || pos+4 > len(wire) {
			return nil, errDNSAnswer
		}
		pos += 4
	}
	count := int(binary.BigEndian.Uint16(wire[6:8])) + int(binary.BigEndian.Uint16(wire[8:10])) + int(binary.BigEndian.Uint16(wire[10:12]))
	if count > 256 {
		return nil, errDNSAnswer
	}
	var offsets []int
	for i := 0; i < count; i++ {
		if !name() || pos+10 > len(wire) {
			return nil, errDNSAnswer
		}
		if binary.BigEndian.Uint16(wire[pos:]) != uint16(dnsmessage.TypeOPT) {
			offsets = append(offsets, pos+4)
		}
		length := int(binary.BigEndian.Uint16(wire[pos+8:]))
		pos += 10 + length
		if pos > len(wire) {
			return nil, errDNSAnswer
		}
	}
	if pos != len(wire) {
		return nil, errDNSAnswer
	}
	return offsets, nil
}
