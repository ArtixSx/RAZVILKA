package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var ErrEndpointDNS = errors.New("endpoint DNS answer is incomplete or unsafe")

// EndpointDNSResolver supplies real DNS expiry to a tunnel endpoint callback.
// It snapshots one production DoH provider, has no cache or fallback, and does
// not authorize a route. The transaction owner must fence its network/settings
// epoch through guard and wire Resolve into the adapter's EndpointResolver.
type EndpointDNSResolver struct {
	manager  *Manager
	provider Provider
	target   dnsTarget
	guard    func(context.Context) error
	now      func() time.Time
}

func (m *Manager) NewEndpointDNSResolver(profileID string, guard func(context.Context) error) (*EndpointDNSResolver, error) {
	if guard == nil {
		return nil, ErrEndpointDNS
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, err := scopedProfileIdentity(m.doc, profileID); err != nil {
		return nil, err
	}
	profile, _ := profileByID(profileID)
	provider, _ := providerByIDFor(profile.ProviderID, m.doc)
	if len(provider.Endpoints) == 0 || len(provider.Endpoints) > 16 {
		return nil, ErrEndpointDNS
	}
	for _, endpoint := range provider.Endpoints {
		if endpoint.Transport != "doh" {
			continue
		}
		if target, ok := endpointProbeTarget(endpoint, false); ok && target.detailedDoH != nil {
			return &EndpointDNSResolver{manager: m, provider: cloneProvider(provider), target: target, guard: guard}, nil
		}
	}
	return nil, ErrEndpointDNS
}

func (r *EndpointDNSResolver) clock() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

func (r *EndpointDNSResolver) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.guard(ctx); err != nil {
		return err
	}
	r.manager.mu.RLock()
	current, exists := providerByIDFor(r.provider.ID, r.manager.doc)
	r.manager.mu.RUnlock()
	if !exists || !reflect.DeepEqual(current, r.provider) {
		return ErrServiceDNSChanged
	}
	return ctx.Err()
}

// Resolve returns all A and AAAA addresses, bounded to 32 in total, only after
// both queries complete through the same DoH endpoint and alias chain. A valid
// NODATA reply may accompany one positive family; NXDOMAIN cannot. Unknown or
// zero lifetimes return zero expiry, never an invented lease. Positive expiry
// is the earliest query-start + min(CNAME/address/SOA TTL minus HTTP Age).
func (r *EndpointDNSResolver) Resolve(parent context.Context, hostname string) ([]netip.Addr, time.Time, error) {
	host, err := normalizeCandidateHostname(hostname)
	if err != nil || host == "home.arpa" {
		return nil, time.Time{}, ErrEndpointDNS
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, time.Time{}, ErrEndpointDNS
	}
	ctx, cancel := context.WithTimeout(parent, endpointProbeTimeout)
	defer cancel()
	var addresses []netip.Addr
	var chain []string
	var expiry time.Time
	noncacheable := false
	began := r.clock()
	for i, family := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if err := r.check(ctx); err != nil {
			return nil, time.Time{}, err
		}
		started := r.clock()
		// Inspect the entire wire for mixed private answers, including glue.
		target := r.target
		exchange := target.detailedDoH
		target.detailedDoH = func(ctx context.Context, endpoint string, query []byte, local bool) (dohResponse, error) {
			response, err := exchange(ctx, endpoint, query, local)
			if err == nil {
				err = validatePublicDNSResources(response.wire)
			}
			return response, err
		}
		details, err := exchangeCandidateDNSDetailed(ctx, target, host, family)
		if err != nil && !errors.Is(err, errDNSNoAddress) {
			return nil, time.Time{}, err
		}
		if err := r.check(ctx); err != nil {
			return nil, time.Time{}, err
		}
		if r.clock().Before(started) || started.Before(began) {
			return nil, time.Time{}, ErrEndpointDNS
		}
		if i == 0 {
			chain = details.CNAMEChain
		} else if !slices.Equal(chain, details.CNAMEChain) {
			return nil, time.Time{}, ErrEndpointDNS
		}
		for _, alias := range details.CNAMEChain {
			if normalized, err := normalizeCandidateHostname(alias); err != nil || normalized == "home.arpa" {
				return nil, time.Time{}, ErrEndpointDNS
			}
		}
		addresses = append(addresses, details.Addresses...)
		if len(addresses) > 32 {
			return nil, time.Time{}, ErrEndpointDNS
		}
		ttl := details.TTLSeconds
		if details.NegativeKind == "nodata" {
			ttl = details.NegativeTTLSeconds
		}
		if ttl == nil || *ttl == 0 {
			noncacheable = true
			continue
		}
		familyExpiry := started.Add(time.Duration(*ttl) * time.Second)
		if expiry.IsZero() || familyExpiry.Before(expiry) {
			expiry = familyExpiry
		}
	}
	if len(addresses) == 0 {
		return nil, time.Time{}, ErrEndpointDNS
	}
	if err := r.check(ctx); err != nil {
		return nil, time.Time{}, err
	}
	finished := r.clock()
	if finished.Before(began) || !expiry.IsZero() && !expiry.After(finished) {
		return nil, time.Time{}, ErrEndpointDNS
	}
	if noncacheable {
		expiry = time.Time{}
	}
	return addresses, expiry, nil
}

func validatePublicDNSResources(wire []byte) error {
	if _, err := dnsWireTTLOffsets(wire); err != nil {
		return err
	}
	var message dnsmessage.Message
	if len(wire) > 65535 || message.Unpack(wire) != nil {
		return errDNSAnswer
	}
	if !message.RecursionDesired || message.CheckingDisabled {
		return errDNSAnswer // match the flags of buildDNSQueryFor
	}
	opt := 0
	for _, section := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
		for _, rr := range section {
			var address netip.Addr
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				address = netip.AddrFrom4(body.A)
			case *dnsmessage.AAAAResource:
				address = netip.AddrFrom16(body.AAAA)
			case *dnsmessage.OPTResource:
				opt++
				if opt > 1 || rr.Header.Name.String() != "." || rr.Header.TTL&0xffff7fff != 0 {
					return errDNSAnswer // no hidden extended RCODE/version/flags
				}
				continue
			default:
				continue
			}
			if rr.Header.Class != dnsmessage.ClassINET || !publicDNSAddress(address) {
				return errDNSAnswer
			}
		}
	}
	return nil
}
