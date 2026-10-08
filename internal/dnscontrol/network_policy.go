package dnscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var ErrNetworkPolicyDNS = errors.New("network policy DNS admission unavailable")
var ErrNetworkPolicyDNSOutside = errors.New("client outside owned network policy DNS")

type NetworkPolicyDNSAuthority struct {
	Generation      string                         `json:"generation"`
	ControlEpoch    uint64                         `json:"control_epoch"`
	BindingRevision uint64                         `json:"binding_revision"`
	Exclusions      NetworkPolicyDNSExclusionStamp `json:"exclusions"`
}

// Admission is supplied by the same physical LAN/device owner used by the
// traffic gate. A DNS socket's peer IP alone cannot prove ingress or MAC.
type NetworkPolicyDNSAdmission struct {
	Authority NetworkPolicyDNSAuthority
	Ingress   string
	DeviceID  string
	// managed requires an applicable active include after every effective
	// exclusion. baseline covers unmatched/empty lists and excluded resources;
	// outside covers excluded clients. The same policy owner supplies this
	// fresh decision and fences changes to its include/exclusion revision.
	Kind string // managed, baseline, outside, refused
}

// The resolver composes the existing strict service resolver with one
// explicitly selected common provider for admitted active-list traffic only.
// A missing service binding does not prove a positive match; admission must
// supply it. Service failures/refusals never become NoMatch. No independent
// cache, scheduler or owner is created; the existing service ledger is reused.
type NetworkPolicyDNSResolver struct {
	authority  NetworkPolicyDNSAuthority
	service    *ScopedDNSResolver
	defaultDNS *ScopedDNSResolver
	choice     scopedDNSChoice
	guard      func(context.Context) error
	admit      func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error)
	baseline   func(context.Context, []byte) ([]byte, error)
	now        func() time.Time
	exclusions *NetworkPolicyDNSExclusions
}

func (m *Manager) NewNetworkPolicyDNSResolver(ctx context.Context, defaultProfile string, bindings []ClientDNSBinding, authority NetworkPolicyDNSAuthority, guard func(context.Context) error, admit func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error), exclusions *NetworkPolicyDNSExclusions) (*NetworkPolicyDNSResolver, error) {
	if ctx == nil || m == nil || len(authority.Generation) != 64 || strings.Trim(authority.Generation, "0123456789abcdef") != "" || authority.ControlEpoch == 0 || authority.BindingRevision == 0 || guard == nil || admit == nil || len(bindings) > 128 {
		return nil, ErrNetworkPolicyDNS
	}
	if exclusions == nil || exclusions.self != exclusions || authority.Exclusions != exclusions.Stamp() {
		return nil, ErrNetworkPolicyDNS
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	if err := exclusions.current(ctx); err != nil {
		return nil, err
	}
	// Production trust is the same existing provider review, not successful
	// diagnostic reachability or a caller-supplied capability bit.
	m.mu.RLock()
	if _, err := scopedProfileIdentity(m.doc, defaultProfile); err != nil {
		m.mu.RUnlock()
		return nil, err
	}
	serviceProviders := make(map[string]Provider)
	for _, b := range bindings {
		if _, err := scopedProfileIdentity(m.doc, b.ProfileID); err != nil {
			m.mu.RUnlock()
			return nil, err
		}
		profile, _ := profileByID(b.ProfileID)
		provider, _ := providerByIDFor(profile.ProviderID, m.doc)
		serviceProviders[provider.ID] = cloneProvider(provider)
	}
	profile, ok := profileByID(defaultProfile)
	provider, exists := providerByIDFor(profile.ProviderID, m.doc)
	provider = cloneProvider(provider)
	m.mu.RUnlock()
	if !ok || !exists || !provider.Configured || provider.TrustedLocal || provider.Scope == "negative-control" {
		return nil, ErrNetworkPolicyDNS
	}
	var choice scopedDNSChoice
	for _, endpoint := range provider.Endpoints {
		if endpoint.Transport == "doh" {
			if target, valid := endpointProbeTarget(endpoint, false); valid && target.detailedDoH != nil {
				choice = scopedDNSChoice{provider: provider, target: target}
				break
			}
		}
	}
	if choice.target.detailedDoH == nil {
		return nil, ErrNetworkPolicyDNS
	}
	r := &NetworkPolicyDNSResolver{authority: authority, choice: choice, guard: guard, admit: admit, now: time.Now, exclusions: exclusions}
	r.defaultDNS = &ScopedDNSResolver{manager: m, choices: map[scopedDNSKey]scopedDNSChoice{}, guard: guard}
	if len(bindings) != 0 {
		var err error
		r.service, err = m.NewScopedDNSResolver(bindings, guard)
		if err != nil {
			return nil, err
		}
		// Both trust validation and the accepted provider identity originate
		// in the snapshot above. A concurrent edit while the existing resolver
		// is constructed must not acquire a new, unreviewed identity.
		for _, choice := range r.service.choices {
			if !reflect.DeepEqual(serviceProviders[choice.provider.ID], choice.provider) {
				return nil, ErrServiceDNSChanged
			}
		}
	}
	if err := exclusions.current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// UseReviewedBaseline is optional and must be configured before use. It is
// called ONLY for a baseline name decision, never an excluded device or an
// implicit fallback after a failed selected/common provider. The owner reviews
// its loop freedom and exact existing resolver identity along with the policy.
func (r *NetworkPolicyDNSResolver) UseReviewedBaseline(exchange func(context.Context, []byte) ([]byte, error)) error {
	if r == nil || exchange == nil {
		return ErrNetworkPolicyDNS
	}
	r.baseline = exchange
	return nil
}

func (r *NetworkPolicyDNSResolver) admission(ctx context.Context, client netip.Addr, name string) (NetworkPolicyDNSAdmission, error) {
	var a NetworkPolicyDNSAdmission
	if r == nil || r.guard == nil || r.admit == nil || !client.IsValid() || client.Is4In6() || client.Zone() != "" || client.IsUnspecified() || client.IsMulticast() {
		return a, ErrNetworkPolicyDNS
	}
	if err := errors.Join(ctx.Err(), r.guard(ctx)); err != nil {
		return a, err
	}
	a, err := r.admit(ctx, client, name)
	if err != nil {
		return a, err
	}
	if err := ctx.Err(); err != nil {
		return a, err
	}
	if a.Authority != r.authority || a.Ingress == "" {
		return a, ErrNetworkPolicyDNS
	}
	if a.Kind == "managed" || a.Kind == "baseline" {
		outside, err := r.exclusions.clientExcluded(ctx, client, a.DeviceID)
		if err != nil {
			return a, err
		}
		if outside {
			a.Kind = "outside"
			return a, ErrNetworkPolicyDNSOutside
		}
	}
	switch a.Kind {
	case "outside":
		return a, ErrNetworkPolicyDNSOutside
	case "baseline":
		return a, r.exclusions.current(ctx)
	case "managed":
		excluded, err := r.queryExcluded(ctx, a, name)
		if err != nil {
			return a, err
		}
		if excluded {
			a.Kind = "baseline"
			return a, nil
		}
		// A selected provider's trust/availability cannot prevent an excluded
		// or unmatched resource from keeping the separately reviewed baseline.
		if r.defaultDNS == nil {
			return a, ErrNetworkPolicyDNS
		}
		if err := r.defaultDNS.check(ctx, r.choice); err != nil {
			return a, err
		}
		return a, nil
	default:
		return a, ErrNetworkPolicyDNS
	}
}

func (r *NetworkPolicyDNSResolver) Resolve(ctx context.Context, client netip.Addr, query []byte) ([]byte, error) {
	return r.resolve(ctx, client, query, nil)
}

func (r *NetworkPolicyDNSResolver) resolve(ctx context.Context, client netip.Addr, query []byte, accepted *NetworkPolicyDNSAdmission) ([]byte, error) {
	q, _, err := scopedBaselineQuestion(query)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), "."))
	a, err := r.admission(ctx, client, name)
	if err != nil {
		return nil, err
	}
	var wire []byte
	if a.Kind == "baseline" {
		if r.baseline == nil {
			return nil, ErrNetworkPolicyDNS
		}
		bounded, cancel := context.WithTimeout(ctx, endpointProbeTimeout)
		defer cancel()
		wire, err = r.baseline(bounded, slicesDNSWire(query))
	} else if r.service != nil {
		key := scopedDNSKey{client, name}
		if _, match := r.service.choices[key]; match {
			// Unsupported types and provider changes are matched refusals.
			wire, err = r.service.resolve(ctx, client, query, func(answer []byte) error {
				return r.checkAnswer(ctx, a, name, answer)
			})
		} else {
			wire, err = r.resolveDefault(ctx, query, q)
		}
	} else {
		wire, err = r.resolveDefault(ctx, query, q)
	}
	if err != nil {
		return nil, err
	}
	resolvedAt := r.now()
	if err := networkPolicyDNSAnswer(query, wire); err != nil {
		return nil, err
	}
	current, err := r.admission(ctx, client, name)
	if err != nil || current != a {
		return nil, errors.Join(err, ErrNetworkPolicyDNS)
	}
	if err := r.checkAnswer(ctx, a, name, wire); err != nil {
		return nil, err
	}
	if accepted != nil {
		*accepted = a
	}
	return r.ageResidence(wire, resolvedAt)
}

func (r *NetworkPolicyDNSResolver) ageResidence(wire []byte, started time.Time) ([]byte, error) {
	elapsed := r.now().Sub(started)
	if elapsed < 0 {
		return nil, errDNSAnswer
	}
	var answer dnsmessage.Message
	if answer.Unpack(wire) != nil {
		return nil, errDNSAnswer
	}
	return ageDNSWire(wire, uint64((elapsed+time.Second-1)/time.Second), networkPolicyDNSNegative(answer))
}

// A CNAME in Answers does not make a NOERROR response positive for the
// requested type. Follow its owner names to the relevant RRset before aging
// the SOA negative lease (RFC 2308 sections 2.2 and 5). Unrelated records must
// not preserve a longer SOA TTL. This classifies the wire; it creates no cache
// or domain/flow authority.
func networkPolicyDNSNegative(answer dnsmessage.Message) bool {
	if answer.RCode == dnsmessage.RCodeNameError || len(answer.Answers) == 0 {
		return true
	}
	if answer.RCode != dnsmessage.RCodeSuccess || len(answer.Questions) != 1 {
		return false
	}
	hasSOA := false
	for _, rr := range answer.Authorities {
		hasSOA = hasSOA || rr.Header.Type == dnsmessage.TypeSOA
	}
	if !hasSOA {
		return false
	}
	q := answer.Questions[0]
	aliases := make(map[string]string)
	relevant := make(map[string]bool)
	for _, rr := range answer.Answers {
		if rr.Header.Class != q.Class {
			continue
		}
		name := strings.ToLower(rr.Header.Name.String())
		if rr.Header.Type == q.Type || q.Type == dnsmessage.TypeALL {
			relevant[name] = true
		}
		if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
			target := strings.ToLower(cname.CNAME.String())
			if old, duplicate := aliases[name]; duplicate && old != target {
				aliases[name] = "" // ambiguity cannot prove a relevant RRset
			} else {
				aliases[name] = target
			}
		}
	}
	name := strings.ToLower(q.Name.String())
	seen := make(map[string]bool)
	for !seen[name] {
		if relevant[name] {
			return false
		}
		seen[name] = true
		next := aliases[name]
		if next == "" {
			break
		}
		name = next
	}
	return true
}

func slicesDNSWire(wire []byte) []byte { return append([]byte(nil), wire...) }

func (r *NetworkPolicyDNSResolver) resolveDefault(ctx context.Context, query []byte, q dnsmessage.Message) ([]byte, error) {
	if err := r.defaultDNS.check(ctx, r.choice); err != nil {
		return nil, err
	}
	started := r.now()
	bounded, cancel := context.WithTimeout(ctx, endpointProbeTimeout)
	defer cancel()
	response, err := r.choice.target.detailedDoH(bounded, r.choice.target.endpoint, slicesDNSWire(query), false)
	if err != nil {
		return nil, err
	}
	if err := r.defaultDNS.check(ctx, r.choice); err != nil {
		return nil, err
	}
	if err := networkPolicyDNSAnswer(query, response.wire); err != nil {
		return nil, err
	}
	var answer dnsmessage.Message
	if answer.Unpack(response.wire) != nil {
		return nil, errDNSAnswer
	}
	elapsed := r.now().Sub(started)
	if elapsed < 0 {
		return nil, errDNSAnswer
	}
	seconds := uint64((elapsed + time.Second - 1) / time.Second)
	if response.age > ^uint64(0)-seconds {
		return nil, errDNSAnswer
	}
	negative := networkPolicyDNSNegative(answer)
	// No second DNS cache. Preserve arbitrary standard types/EDNS and consume
	// HTTP Age plus local residence in the original wire, without repacking.
	return ageDNSWire(response.wire, response.age+seconds, negative)
}

func networkPolicyDNSAnswer(query, wire []byte) error {
	var q, a dnsmessage.Message
	if len(wire) < 12 || len(wire) > 65535 || q.Unpack(query) != nil || a.Unpack(wire) != nil || !a.Response || a.ID != q.ID || a.OpCode != q.OpCode || a.CheckingDisabled != q.CheckingDisabled || a.RecursionDesired != q.RecursionDesired || !reflect.DeepEqual(a.Questions, q.Questions) {
		return errDNSAnswer
	}
	if _, err := dnsWireTTLOffsets(wire); err != nil {
		return err
	}
	opt := 0
	for _, section := range [][]dnsmessage.Resource{a.Answers, a.Authorities, a.Additionals} {
		for _, rr := range section {
			if rr.Header.Type == dnsmessage.TypeOPT {
				opt++
				if opt > 1 || rr.Header.Name.String() != "." {
					return errDNSAnswer
				}
			}
		}
	}
	return nil
}

// Publish is the final short owner admission boundary. The owner atomically
// rechecks its durable Stop/generation, client binding and gate readback with
// sending the wire. A check followed by an unrelated socket write is weaker.
func (r *NetworkPolicyDNSResolver) Publish(ctx context.Context, client netip.Addr, query []byte, publish NetworkPolicyDNSPublisher, send func([]byte) error) error {
	if publish == nil || send == nil {
		return ErrNetworkPolicyDNS
	}
	var before NetworkPolicyDNSAdmission
	wire, err := r.resolve(ctx, client, query, &before)
	if err != nil {
		return err
	}
	resolvedAt := r.now()
	q, _, err := scopedBaselineQuestion(query)
	if err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), "."))
	return publish(ctx, before, func() error {
		// The original owner acquires its gate before entering this leaf. All
		// owner/catalog/provider checks finish before the Store observation.
		a, err := r.admission(ctx, client, name)
		if err != nil {
			return err
		}
		if a != before {
			return ErrNetworkPolicyDNS
		}
		if a.Kind == "managed" && r.service != nil {
			if choice, selected := r.service.choices[scopedDNSKey{client, name}]; selected {
				if err := r.service.check(ctx, choice); err != nil {
					return err
				}
			}
		}
		targets, err := r.answerTargets(ctx, a, name, wire)
		if err != nil {
			return err
		}
		excluded, err := r.exclusions.observe(ctx, targets, func() error {
			final, err := r.ageResidence(wire, resolvedAt)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return send(final)
		})
		if err != nil {
			return err
		}
		if excluded {
			return ErrNetworkPolicyDNSExcluded
		}
		return nil
	})
}

// This enriches detached existing observations. It does not identify a flow
// or publish fake-IP, ipsets, routes or domain authority of any kind.
type NetworkPolicyDNSObservation struct {
	Authority     NetworkPolicyDNSAuthority
	ObservationID string
	ScopedDNSObservation
}

func (r *NetworkPolicyDNSResolver) Observations(ctx context.Context) ([]NetworkPolicyDNSObservation, error) {
	if r == nil {
		return nil, ErrNetworkPolicyDNS
	}
	if err := errors.Join(ctx.Err(), r.guard(ctx)); err != nil {
		return nil, err
	}
	if err := r.exclusions.current(ctx); err != nil {
		return nil, err
	}
	if r.service == nil {
		return []NetworkPolicyDNSObservation{}, nil
	}
	observations, err := r.service.Observations(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]NetworkPolicyDNSObservation, 0, len(observations))
	for _, o := range observations {
		a, err := r.admission(ctx, o.Client, o.Domain)
		if errors.Is(err, ErrNetworkPolicyDNSOutside) {
			continue
		} else if err != nil {
			return nil, err
		}
		if a.Kind != "managed" {
			// A retained historical cache entry cannot re-propose a resource
			// after exclusion/deactivation or become new positive authority.
			continue
		}
		names := append([]string{o.Domain}, o.Details.CNAMEChain...)
		targets, err := r.exclusions.targets(ctx, a.DeviceID, names, o.Details.Addresses)
		if err != nil {
			return nil, err
		}
		excluded, err := r.exclusions.observe(ctx, targets, nil)
		if err != nil {
			return nil, err
		}
		if excluded {
			continue
		}
		value := NetworkPolicyDNSObservation{Authority: r.authority, ScopedDNSObservation: o}
		data, _ := json.Marshal(struct {
			Authority                NetworkPolicyDNSAuthority
			Client                   netip.Addr
			Domain, Family, Provider string
			CD, DO                   bool
			ObservedAt               time.Time
			Details                  AnswerDetails
		}{r.authority, o.Client, o.Domain, o.Family, o.ProviderID, o.CheckingDisabled, o.DNSSECRequested, o.ObservedAt, o.Details})
		h := sha256.Sum256(data)
		value.ObservationID = hex.EncodeToString(h[:])
		result = append(result, value)
	}
	if err := errors.Join(ctx.Err(), r.guard(ctx)); err != nil {
		return nil, err
	}
	if err := r.exclusions.current(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
