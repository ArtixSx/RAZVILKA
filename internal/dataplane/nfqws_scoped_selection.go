package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// NFQWSScopedMatch retains one complete DEFAULT literal-CIDR tuple. These are
// immutable comparison inputs, not scope consent or kernel effect authority.
// First capability is one original selected logical service and saved family.
type NFQWSScopedMatch struct {
	ServiceID, Origin, Route, Ingress string
	Source, Destination               netip.Prefix
	Protocol                          string
	FirstPort, LastPort               uint16
}

// NFQWSScopedSelection retains the actual original StrategyLab review. Its
// Spec accessor cannot construct an execution resource or an active process.
// The shared Apply owner separately retains scope, component, LAN and network
// owners through Start/CAS/final ACK and receipt-owned cleanup.
type NFQWSScopedSelection struct {
	self      *NFQWSScopedSelection
	mu        sync.Mutex
	closed    bool
	source    *strategylab.SelectedCandidateReview
	reference strategylab.SelectedCandidateReference
	spec      NFQWSScopedSpec
	prepared  *NFQWSActiveMaterial
	plan      Plan
}

// Private untimed reader: exact immutable tuples are checked without compiling
// chains or supplying placeholder session IDs, deadlines or command hashes.
func reviewNFQWSScopedPreparedSelection(ctx context.Context, material *NFQWSActiveMaterial, reference strategylab.SelectedCandidateReference, expected Plan, matches []NFQWSScopedMatch) (*NFQWSScopedSelection, error) {
	if material == nil || material.self != material || len(matches) == 0 || len(matches) > 1024 {
		return nil, ErrNFQWSScopedOwner
	}
	spec := material.intentSpec()
	spec.Candidate.ServiceID, spec.Candidate.IPFamily = reference.ServiceID, reference.IPFamily
	for _, traffic := range reference.Traffic {
		if traffic.IPFamily != reference.IPFamily {
			return nil, ErrNFQWSScopedOwner
		}
		spec.Candidate.Traffic = append(spec.Candidate.Traffic, NFQWSScopedTraffic{Protocol: traffic.Protocol, First: traffic.First, Last: traffic.Last})
	}
	spec.Matches = slices.Clone(matches)
	checked, err := validateNFQWSScopedIntent(expected, spec)
	if err != nil {
		return nil, err
	}
	r := &NFQWSScopedSelection{source: material.source, reference: reference, spec: checked, prepared: material, plan: cloneExecutionResourcePlan(expected)}
	r.self = r
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// ReviewNFQWSScopedSelection reads the original source and compares the full
// reference consumed by DEFAULT. A matching DTO alone never creates this
// handle. spec's command/queue identity is still only compiler input here.
// This reader neither launches nor validates natively nor acquires a journal.
func ReviewNFQWSScopedSelection(ctx context.Context, source *strategylab.SelectedCandidateReview, expectedReference strategylab.SelectedCandidateReference, expected Plan, spec NFQWSScopedSpec, matches []NFQWSScopedMatch) (*NFQWSScopedSelection, error) {
	if source == nil || len(matches) == 0 || len(matches) > 1024 || len(spec.Matches) != 0 || spec.Candidate.ServiceID != "" || spec.Candidate.IPFamily != "" {
		return nil, ErrNFQWSScopedOwner
	}
	reference, err := source.Reference(ctx)
	if err != nil || !reflect.DeepEqual(reference, expectedReference) {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	// The original producer validates all profile filters, saved transport and
	// family. Only its values supply the candidate's traffic comparison input.
	if spec.Candidate.ID != reference.CandidateID || spec.Candidate.Incarnation != reference.Incarnation {
		return nil, ErrNFQWSScopedOwner
	}
	spec = spec.Clone()
	spec.Candidate.ServiceID, spec.Candidate.IPFamily = reference.ServiceID, reference.IPFamily
	spec.Candidate.Traffic = nil
	for _, traffic := range reference.Traffic {
		if traffic.IPFamily != reference.IPFamily {
			return nil, ErrNFQWSScopedOwner
		}
		spec.Candidate.Traffic = append(spec.Candidate.Traffic, NFQWSScopedTraffic{Protocol: traffic.Protocol, First: traffic.First, Last: traffic.Last})
	}
	spec.Matches = slices.Clone(matches)
	compiled, err := CompileNFQWSScopedPlan(expected, spec)
	if err != nil {
		return nil, err
	}
	r := &NFQWSScopedSelection{source: source, reference: reference, spec: compiled.Spec()}
	r.self = r
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *NFQWSScopedSelection) Spec() NFQWSScopedSpec {
	if r == nil || r.self != r {
		return NFQWSScopedSpec{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return NFQWSScopedSpec{}
	}
	return r.spec.Clone()
}

// Current remains read-only and acquires no App/Store/Gate authority. The
// original review checks its actual held component lease and whole source.
func (r *NFQWSScopedSelection) Current(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.source == nil {
		return ErrNFQWSScopedOwner
	}
	if r.prepared != nil {
		if r.prepared.self != r.prepared || r.prepared.source != r.source || !reflect.DeepEqual(r.prepared.reference, r.reference) || r.spec.SessionID != "" || r.spec.CommandSHA256 != "" {
			return ErrNFQWSScopedOwner
		}
		if _, err := validateNFQWSScopedIntent(r.plan, r.spec); err != nil {
			return err
		}
	}
	reference, err := r.source.Reference(ctx)
	if err != nil || !reflect.DeepEqual(reference, r.reference) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return nil
}

// Close retires only this comparison consumer. The actual Apply owner owns
// source.Close and runtime.Close AFTER process and COMMON cleanup have joined.
func (r *NFQWSScopedSelection) Close() error {
	if r == nil || r.self != r {
		return ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func nfqwsScopedLogicalService(route Route) string {
	if route.LogicalServiceID != "" {
		return route.LogicalServiceID
	}
	return route.ServiceID
}

func nfqwsScopedMatchKey(route Route, ingress string, source, destination netip.Prefix, traffic NFQWSScopedTraffic) string {
	return nfqwsScopedTupleKey(NFQWSScopedMatch{ServiceID: nfqwsScopedLogicalService(route), Origin: route.NetworkPolicyRole, Route: route.Resolved,
		Ingress: ingress, Source: source, Destination: destination, Protocol: traffic.Protocol, FirstPort: traffic.First, LastPort: traffic.Last})
}

func nfqwsScopedCellKey(m NFQWSScopedMatch) string {
	return strings.Join([]string{m.ServiceID, m.Origin, m.Route, m.Ingress, m.Source.String(), m.Destination.String()}, "\x00")
}

func nfqwsScopedTupleKey(m NFQWSScopedMatch) string {
	return nfqwsScopedCellKey(m) + "\x00" + m.Protocol + "\x00" + strconv.Itoa(int(m.FirstPort)) + ":" + strconv.Itoa(int(m.LastPort))
}

func nfqwsScopedMatchSet(matches []NFQWSScopedMatch) map[string]bool {
	result := make(map[string]bool, len(matches))
	for _, m := range matches {
		result[nfqwsScopedTupleKey(m)] = true
	}
	return result
}

func nfqwsScopedValidateMatches(expected Plan, spec *NFQWSScopedSpec) error {
	candidate := spec.Candidate
	if len(spec.Matches) == 0 {
		if candidate.ServiceID != "" || candidate.IPFamily != "" {
			return ErrNFQWSScopedOwner
		}
		return nil // Preserve old isolated, non-production compiler images.
	}
	if len(spec.Matches) > 1024 || candidate.ServiceID == "" || candidate.ServiceID == "default" || strings.TrimSpace(candidate.ServiceID) != candidate.ServiceID || strings.ContainsAny(candidate.ServiceID, "|\x00\r\n") || len(candidate.ServiceID) > 128 || candidate.IPFamily != "ipv4" && candidate.IPFamily != "ipv6" {
		return ErrNFQWSScopedOwner
	}
	family4 := candidate.IPFamily == "ipv4"
	cells, tuples := map[string]bool{}, map[string]bool{}
	for _, m := range spec.Matches {
		if m.ServiceID != candidate.ServiceID || m.Origin != "override" || AdapterID(m.Route) != "nfqws2" || len(m.Route) > 256 || len(m.Ingress) > 16 || !m.Source.IsValid() || !m.Destination.IsValid() || m.Source != m.Source.Masked() || m.Destination != m.Destination.Masked() || m.Source.Addr().Is4In6() || m.Destination.Addr().Is4In6() || m.Source.Addr().Zone() != "" || m.Destination.Addr().Zone() != "" || m.Source.Addr().Is4() != family4 || m.Destination.Addr().Is4() != family4 || !nfqwsScopedPublic(m.Destination) {
			return ErrNFQWSScopedOwner
		}
		// DEFAULT's current capability emits the original canonical coverage
		// cells. A range split/merge needs an explicit future compiler contract;
		// refusing it prevents replacing an exact tuple with a wider filter.
		if !slices.Contains(candidate.Traffic, NFQWSScopedTraffic{Protocol: m.Protocol, First: m.FirstPort, Last: m.LastPort}) || m.FirstPort == 0 || m.LastPort < m.FirstPort {
			return ErrNFQWSScopedOwner
		}
		key := nfqwsScopedTupleKey(m)
		if tuples[key] {
			return ErrNFQWSScopedOwner
		}
		tuples[key], cells[nfqwsScopedCellKey(m)] = true, true
	}
	// Compare every projected generic route cell with the full exact tuples.
	// The generic envelope is never used to infer ports, origin or family.
	covered, count := map[string]bool{}, 0
	for _, route := range expected.Routes {
		if AdapterID(route.Resolved) != "nfqws2" {
			continue
		}
		if nfqwsScopedLogicalService(route) != candidate.ServiceID || route.NetworkPolicyRole != "override" || len(route.Domains) != 0 || len(route.Ingress) == 0 || len(route.Sources) == 0 || len(route.CIDRs) == 0 {
			return ErrNFQWSScopedOwner
		}
		for _, ingress := range route.Ingress {
			for _, value := range route.Sources {
				source, err := nfqwsScopedPrefix(value)
				if err != nil || source.Addr().Is4() != family4 {
					return ErrNFQWSScopedOwner
				}
				for _, value := range route.CIDRs {
					destination, err := nfqwsScopedPrefix(value)
					if err != nil || destination.Addr().Is4() != family4 {
						return ErrNFQWSScopedOwner
					}
					cell := nfqwsScopedCellKey(NFQWSScopedMatch{ServiceID: candidate.ServiceID, Origin: route.NetworkPolicyRole, Route: route.Resolved, Ingress: ingress, Source: source, Destination: destination})
					if !cells[cell] {
						return ErrNFQWSScopedOwner
					}
					covered[cell] = true
					count++
					if count > 2048 {
						return ErrNFQWSScopedOwner
					}
				}
			}
		}
	}
	if len(covered) != len(cells) {
		return ErrNFQWSScopedOwner
	}
	sort.Slice(spec.Matches, func(i, j int) bool {
		return nfqwsScopedTupleKey(spec.Matches[i]) < nfqwsScopedTupleKey(spec.Matches[j])
	})
	return nil
}
