package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/config"
	"golang.org/x/net/dns/dnsmessage"
)

var ErrNetworkPolicyDNSExcluded = errors.New("DNS answer contains an excluded resource")

// This stamp is a comparison image only. It cannot replace the original Store,
// owner admission, retained catalog or current physical/gate proof.
type NetworkPolicyDNSExclusionStamp struct {
	ConfigRevision    uint64 `json:"config_revision"`
	PolicyRevision    uint64 `json:"policy_revision"`
	ExclusionRevision uint64 `json:"exclusion_revision"`
	Digest            string `json:"digest"`
}

// The retained policy owner supplies ALL catalog identities for this name,
// including disabled/excluded definitions. This is negative classification,
// never a positive DNS/flow grant. Missing or ambiguous catalog evidence must
// return an error. The callback runs outside the Store observation lock.
type NetworkPolicyDNSServiceIdentities func(context.Context, string) ([]string, error)

type NetworkPolicyDNSExclusions struct {
	self       *NetworkPolicyDNSExclusions
	store      *config.Store
	expected   config.Config
	stamp      NetworkPolicyDNSExclusionStamp
	identities NetworkPolicyDNSServiceIdentities
	revoked    atomic.Bool
}

func NewNetworkPolicyDNSExclusions(ctx context.Context, store *config.Store, expected config.Config, identities NetworkPolicyDNSServiceIdentities) (*NetworkPolicyDNSExclusions, error) {
	if ctx == nil || store == nil || identities == nil {
		return nil, ErrNetworkPolicyDNS
	}
	// Get supplies the actual Store's detached deep copy, retaining nil/empty
	// distinctions and all fields. A copied revision/digest is insufficient.
	actual := store.Get()
	if !reflect.DeepEqual(actual, expected) {
		return nil, config.ErrRevisionChanged
	}
	f := &NetworkPolicyDNSExclusions{store: store, expected: actual, identities: identities}
	f.self = f
	if err := store.WithResourceExclusionObservation(ctx, actual, func(set config.EffectiveExclusionSet) error {
		f.stamp = NetworkPolicyDNSExclusionStamp{actual.Revision, set.PolicyRevision, set.Revision, set.Digest}
		return nil
	}); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *NetworkPolicyDNSExclusions) Stamp() NetworkPolicyDNSExclusionStamp {
	if f == nil || f.self != f {
		return NetworkPolicyDNSExclusionStamp{}
	}
	return f.stamp
}

// The only callback under the SAME Store RLock is a bounded closed leaf.
// It MUST NOT call Store, owner.Current, the gate, providers or protocol IO.
// At publication the original owner holds its gate lease outside this lock;
// the leaf may perform only prepared local publication: the original durable
// control owner's raw lock/marker checks and bounded socket write. That control
// bracket must admit Gate outside this Store lock and never reenter Gate/Store.
func (f *NetworkPolicyDNSExclusions) observe(ctx context.Context, targets []config.ResourceTarget, leaf func() error) (bool, error) {
	return f.observeDecision(ctx, func(ctx context.Context, set config.EffectiveExclusionSet) (bool, error) {
		excluded := false
		for _, target := range targets {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			match, err := set.Matches(target)
			if err != nil {
				return false, err
			}
			excluded = excluded || match
		}
		return excluded, nil
	}, leaf)
}

func (f *NetworkPolicyDNSExclusions) clientExcluded(ctx context.Context, client netip.Addr, device string) (bool, error) {
	return f.observeDecision(ctx, func(_ context.Context, set config.EffectiveExclusionSet) (bool, error) {
		if device != "" && slices.Contains(set.Clients.ExcludedDeviceIDs, device) {
			return true, nil
		}
		for _, value := range set.Clients.ExcludedCIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return false, config.ErrResourceExclusions
			}
			if prefix.Contains(client) {
				return true, nil
			}
		}
		return false, nil
	}, nil)
}

// decision is a private, closed in-memory matcher, never an owner callback.
func (f *NetworkPolicyDNSExclusions) observeDecision(ctx context.Context, decision func(context.Context, config.EffectiveExclusionSet) (bool, error), leaf func() error) (bool, error) {
	if ctx == nil || f == nil || f.self != f || f.store == nil || f.identities == nil || f.revoked.Load() {
		return false, ErrNetworkPolicyDNS
	}
	ctx, cancel := context.WithTimeout(ctx, endpointProbeTimeout)
	defer cancel()
	excluded := false
	var callbackErr error
	err := f.store.WithResourceExclusionObservation(ctx, f.expected, func(set config.EffectiveExclusionSet) error {
		stamp := NetworkPolicyDNSExclusionStamp{f.expected.Revision, set.PolicyRevision, set.Revision, set.Digest}
		if stamp != f.stamp {
			return config.ErrRevisionChanged
		}
		excluded, callbackErr = decision(ctx, set)
		if callbackErr != nil {
			return callbackErr
		}
		if err := ctx.Err(); err != nil {
			callbackErr = err
			return err
		}
		if !excluded && leaf != nil {
			callbackErr = leaf()
			return callbackErr
		}
		return nil
	})
	// Once the actual config/disk boundary fails, restoring its old bytes cannot
	// revive this participant. Request cancellation and leaf failures are local.
	if err != nil && callbackErr == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		f.revoked.Store(true)
	}
	return excluded, err
}

func (f *NetworkPolicyDNSExclusions) current(ctx context.Context) error {
	_, err := f.observe(ctx, nil, nil)
	return err
}

func (f *NetworkPolicyDNSExclusions) targets(ctx context.Context, device string, names []string, addresses []netip.Addr) ([]config.ResourceTarget, error) {
	if f == nil || f.self != f || f.identities == nil || len(names) > 129 || len(addresses) > 4096 {
		return nil, ErrNetworkPolicyDNS
	}
	var targets []config.ResourceTarget
	seen := map[string]bool{}
	for _, value := range names {
		// QNAME/CNAME are observed identities, not curated exact/suffix rules.
		name, err := config.ResourceHostname(value)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		ids, err := f.identities(ctx, name)
		if err != nil || len(ids) > 128 {
			return nil, errors.Join(err, ErrNetworkPolicyDNS)
		}
		// Copy immediately; caller-owned slices never enter the Store callback.
		ids = slices.Clone(ids)
		targets = append(targets, config.ResourceTarget{Domain: name, DeviceID: device})
		for _, id := range ids {
			if id == "" {
				return nil, ErrNetworkPolicyDNS
			}
			targets = append(targets, config.ResourceTarget{Domain: name, ServiceID: id, DeviceID: device})
		}
	}
	for _, address := range addresses {
		// An AAAA answer may carry an IPv4-mapped address; its resource is the
		// IPv4 address, which IPv4 exclusions must also match. Sinkhole values
		// of filtering resolvers (0.0.0.0, ::, loopback, link-local, multicast)
		// can never be a bypass destination, so they are no resource to
		// classify. The exclusion set refuses both as unknown identities, which
		// failed the whole publication: the client got no answer and could fall
		// back to another resolver outside the policy. Names are still checked.
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.Zone() != "" {
			continue
		}
		targets = append(targets, config.ResourceTarget{Address: address, DeviceID: device})
	}
	if len(targets) > 512 {
		return nil, ErrNetworkPolicyDNS
	}
	return targets, ctx.Err()
}

func (r *NetworkPolicyDNSResolver) queryExcluded(ctx context.Context, a NetworkPolicyDNSAdmission, name string) (bool, error) {
	if name == "" || a.Kind == "baseline" {
		return false, r.exclusions.current(ctx)
	}
	targets, err := r.resourceTargets(ctx, a.DeviceID, []string{name}, nil)
	if err != nil {
		return false, err
	}
	return r.exclusions.observe(ctx, targets, nil)
}

func (r *NetworkPolicyDNSResolver) answerTargets(ctx context.Context, a NetworkPolicyDNSAdmission, name string, wire []byte) ([]config.ResourceTarget, error) {
	if a.Kind == "baseline" {
		return nil, nil
	}
	names, addresses, err := networkPolicyDNSAnswerResources(name, wire)
	if err != nil {
		return nil, err
	}
	return r.resourceTargets(ctx, a.DeviceID, names, addresses)
}

func (r *NetworkPolicyDNSResolver) resourceTargets(ctx context.Context, device string, names []string, addresses []netip.Addr) ([]config.ResourceTarget, error) {
	if r.operations == nil {
		return r.exclusions.targets(ctx, device, names, addresses)
	}
	var targets []config.ResourceTarget
	err := networkPolicyDNSOperation(ctx, r.operations, func(held context.Context) error {
		var err error
		targets, err = r.exclusions.targets(held, device, names, addresses)
		return err
	})
	return targets, err
}

func (r *NetworkPolicyDNSResolver) checkAnswer(ctx context.Context, a NetworkPolicyDNSAdmission, name string, wire []byte) error {
	targets, err := r.answerTargets(ctx, a, name, wire)
	if err != nil {
		return err
	}
	excluded, err := r.exclusions.observe(ctx, targets, nil)
	if err != nil {
		return err
	}
	if excluded {
		return ErrNetworkPolicyDNSExcluded
	}
	return nil
}

// Traverse only the original question's CNAME chain for name identities.
// Every wire A/AAAA, including unrelated glue, is checked as a negative fact;
// none supplies positive identity or route authority. Conflicting aliases/loops
// or an address beside a CNAME fail closed. Other DNS types remain intact.
func networkPolicyDNSAnswerResources(name string, wire []byte) ([]string, []netip.Addr, error) {
	var answer dnsmessage.Message
	if answer.Unpack(wire) != nil || len(answer.Questions) != 1 || len(answer.Answers) > 4096 {
		return nil, nil, errDNSAnswer
	}
	aliases := map[string]string{}
	addresses := map[string][]netip.Addr{}
	var allAddresses []netip.Addr
	for _, rr := range answer.Answers {
		if rr.Header.Class != dnsmessage.ClassINET {
			continue
		}
		owner := strings.ToLower(strings.TrimSuffix(rr.Header.Name.String(), "."))
		switch body := rr.Body.(type) {
		case *dnsmessage.CNAMEResource:
			target := strings.ToLower(strings.TrimSuffix(body.CNAME.String(), "."))
			if old, ok := aliases[owner]; ok && old != target {
				return nil, nil, errDNSAnswer
			}
			aliases[owner] = target
		case *dnsmessage.AResource:
			address := netip.AddrFrom4(body.A)
			addresses[owner] = append(addresses[owner], address)
			allAddresses = append(allAddresses, address)
		case *dnsmessage.AAAAResource:
			address := netip.AddrFrom16(body.AAAA)
			addresses[owner] = append(addresses[owner], address)
			allAddresses = append(allAddresses, address)
		}
	}
	for _, section := range [][]dnsmessage.Resource{answer.Authorities, answer.Additionals} {
		for _, rr := range section {
			if rr.Header.Class != dnsmessage.ClassINET {
				continue
			}
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				allAddresses = append(allAddresses, netip.AddrFrom4(body.A))
			case *dnsmessage.AAAAResource:
				allAddresses = append(allAddresses, netip.AddrFrom16(body.AAAA))
			}
		}
	}
	var names []string
	seen := map[string]bool{}
	for {
		if seen[name] || len(names) >= 129 {
			return nil, nil, errDNSAnswer
		}
		seen[name] = true
		names = append(names, name)
		next, alias := aliases[name]
		if !alias {
			return names, allAddresses, nil
		}
		if next == "" || len(addresses[name]) != 0 {
			return nil, nil, errDNSAnswer
		}
		name = next
	}
}
