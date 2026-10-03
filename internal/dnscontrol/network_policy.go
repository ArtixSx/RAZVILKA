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
	Generation      string `json:"generation"`
	ControlEpoch    uint64 `json:"control_epoch"`
	BindingRevision uint64 `json:"binding_revision"`
}

// Admission is supplied by the same physical LAN/device owner used by the
// traffic gate. A DNS socket's peer IP alone cannot prove ingress or MAC.
type NetworkPolicyDNSAdmission struct {
	Authority NetworkPolicyDNSAuthority
	Ingress   string
	DeviceID  string
	Kind      string // managed, baseline (explicit site exclusion), outside, refused
}

// The resolver composes the existing strict service resolver with one
// explicitly selected production default provider. Service failures/refusals
// never become NoMatch. No independent cache, scheduler or network owner is
// created; observations come from the service resolver's existing ledger.
type NetworkPolicyDNSResolver struct {
	authority  NetworkPolicyDNSAuthority
	service    *ScopedDNSResolver
	defaultDNS *ScopedDNSResolver
	choice     scopedDNSChoice
	guard      func(context.Context) error
	admit      func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error)
	baseline   func(context.Context, []byte) ([]byte, error)
	now        func() time.Time
}

func (m *Manager) NewNetworkPolicyDNSResolver(defaultProfile string, bindings []ClientDNSBinding, authority NetworkPolicyDNSAuthority, guard func(context.Context) error, admit func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error)) (*NetworkPolicyDNSResolver, error) {
	if m == nil || len(authority.Generation) != 64 || strings.Trim(authority.Generation, "0123456789abcdef") != "" || authority.ControlEpoch == 0 || authority.BindingRevision == 0 || guard == nil || admit == nil || len(bindings) > 128 {
		return nil, ErrNetworkPolicyDNS
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
	r := &NetworkPolicyDNSResolver{authority: authority, choice: choice, guard: guard, admit: admit, now: time.Now}
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
	return r, nil
}

// UseReviewedBaseline is optional and must be configured before use. It is
// called ONLY for an explicit baseline name decision, never an excluded
// device or a failed selected/default provider. The owner reviews its loop
// freedom and exact existing resolver identity along with the policy.
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
	if r.defaultDNS == nil {
		return a, ErrNetworkPolicyDNS
	}
	if err := r.defaultDNS.check(ctx, r.choice); err != nil {
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
	switch a.Kind {
	case "outside":
		return a, ErrNetworkPolicyDNSOutside
	case "managed", "baseline":
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
			wire, err = r.service.Resolve(ctx, client, query)
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
	return ageDNSWire(wire, uint64((elapsed+time.Second-1)/time.Second), answer.RCode == dnsmessage.RCodeNameError || len(answer.Answers) == 0)
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
	negative := answer.RCode == dnsmessage.RCodeNameError || len(answer.Answers) == 0
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
func (r *NetworkPolicyDNSResolver) Publish(ctx context.Context, client netip.Addr, query []byte, send func(context.Context, NetworkPolicyDNSAdmission, []byte) error) error {
	if send == nil {
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
	a, err := r.admission(ctx, client, strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), ".")))
	if err != nil {
		return err
	}
	if a != before {
		return ErrNetworkPolicyDNS
	}
	wire, err = r.ageResidence(wire, resolvedAt)
	if err != nil {
		return err
	}
	return send(ctx, a, wire)
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
	if r.service == nil {
		return []NetworkPolicyDNSObservation{}, nil
	}
	observations, err := r.service.Observations(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]NetworkPolicyDNSObservation, 0, len(observations))
	for _, o := range observations {
		if _, err := r.admission(ctx, o.Client, o.Domain); errors.Is(err, ErrNetworkPolicyDNSOutside) {
			continue
		} else if err != nil {
			return nil, err
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
	return result, nil
}
