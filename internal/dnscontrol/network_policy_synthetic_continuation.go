package dnscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This original lineage records only authored append/publication metadata.
// Neither the lineage nor its digest can issue a mapping or settle a cache.
type syntheticDNSLedgerLineage struct {
	mu     sync.Mutex
	active *NetworkPolicyDNSSyntheticResolver
	ledger syntheticDNSLedger
}

type SyntheticDNSLedgerContinuation struct {
	self     *SyntheticDNSLedgerContinuation
	previous *NetworkPolicyDNSSyntheticResolver
	lineage  *syntheticDNSLedgerLineage
	prefix   syntheticDNSLedger
	digest   string
	used     bool // lineage.mu
}

type SyntheticDNSLedgerContinuationReference struct {
	PrefixSHA256 string
	Count        int
}

func (*SyntheticDNSLedgerContinuation) String() string {
	return "[original closed synthetic DNS ledger continuation]"
}
func (*SyntheticDNSLedgerContinuation) GoString() string {
	return "[original closed synthetic DNS ledger continuation]"
}

// ReviewContinuation freezes the SAME joined source's complete final prefix.
// It supplies no DNS owner replacement, baseline, publication or alias reuse
// authority. The adapter must independently detach its original DNS ownership.
func (r *SyntheticDNSRetirementReview) ReviewContinuation(ctx context.Context) (*SyntheticDNSLedgerContinuation, error) {
	return r.reviewContinuation(ctx, false)
}

// ReviewRetiredContinuation retains the complete original closed prefix for
// a never-issued reservation, including an exhausted 256-row ledger. A full
// token is documentary only: bind still refuses it before another mapping.
// Ordinary continuation admission keeps its original strict <256 bound.
func (r *SyntheticDNSRetirementReview) ReviewRetiredContinuation(ctx context.Context) (*SyntheticDNSLedgerContinuation, error) {
	return r.reviewContinuation(ctx, true)
}

func (r *SyntheticDNSRetirementReview) reviewContinuation(ctx context.Context, retired bool) (*SyntheticDNSLedgerContinuation, error) {
	closed, err := r.ObserveClosed(ctx)
	if err != nil {
		return nil, err
	}
	if retired && closed.PossiblyIssued {
		return nil, ErrSyntheticDNSTransitionPending
	}
	s := r.source
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := syntheticDNSMaxReservations - 1
	if retired {
		limit = syntheticDNSMaxReservations
	}
	if len(s.ledger.Reservations) < 1 || len(s.ledger.Reservations) > limit {
		return nil, ErrSyntheticDNSTransitionPending
	}
	if s.lineage == nil {
		s.lineage = &syntheticDNSLedgerLineage{active: s, ledger: cloneSyntheticDNSLedger(s.ledger)}
	}
	l := s.lineage
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active != s || !reflect.DeepEqual(l.ledger, s.ledger) || !syntheticDNSJoinedSource(s) {
		return nil, ErrSyntheticDNSMapping
	}
	prefix := cloneSyntheticDNSLedger(s.ledger)
	wire, err := json.Marshal(prefix)
	if err != nil {
		return nil, ErrSyntheticDNSMapping
	}
	hash := sha256.Sum256(wire)
	c := &SyntheticDNSLedgerContinuation{previous: s, lineage: l, prefix: prefix, digest: hex.EncodeToString(hash[:])}
	c.self = c
	return c, nil
}

func (c *SyntheticDNSLedgerContinuation) Reference() SyntheticDNSLedgerContinuationReference {
	if c == nil || c.self != c {
		return SyntheticDNSLedgerContinuationReference{}
	}
	return SyntheticDNSLedgerContinuationReference{PrefixSHA256: c.digest, Count: len(c.prefix.Reservations)}
}

// Ordinary fresh resolver/control/admission remain mandatory. Only an
// original one-use continuation permits loading already issued reservations;
// these rows occupy addresses and never become this source's live mappings.
func NewNetworkPolicyDNSSyntheticResolverWithContinuation(ctx, lifetime context.Context, resolver *NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview, root string, definition SyntheticDNSDefinition, publication NetworkPolicyDNSSyntheticPublicationOwner, continuation *SyntheticDNSLedgerContinuation) (*NetworkPolicyDNSSyntheticResolver, error) {
	if continuation == nil {
		return nil, ErrSyntheticDNSMapping
	}
	return newNetworkPolicyDNSSyntheticResolver(ctx, lifetime, resolver, control, root, definition, publication, continuation)
}

func syntheticDNSJoinedSource(s *NetworkPolicyDNSSyntheticResolver) bool {
	if s == nil || s.self != s || !s.closed.Load() {
		return false
	}
	select {
	case <-s.closeDone:
		return s.closeErr == nil
	default:
		return false
	}
}

func (c *SyntheticDNSLedgerContinuation) bind(s *NetworkPolicyDNSSyntheticResolver) error {
	if c == nil || c.self != c || c.lineage == nil || c.previous == nil || s == nil || s.self != s || s == c.previous {
		return ErrSyntheticDNSMapping
	}
	l := c.lineage
	l.mu.Lock()
	defer l.mu.Unlock()
	old := c.previous
	if c.used || l.active != old || !syntheticDNSJoinedSource(old) || s.root != old.root || !os.SameFile(s.anchor, old.anchor) || !reflect.DeepEqual(c.prefix, l.ledger) || !reflect.DeepEqual(s.ledger, c.prefix) || len(c.prefix.Reservations) >= syntheticDNSMaxReservations {
		return ErrSyntheticDNSMapping
	}
	c.used = true
	s.lineage, s.prefixCount = l, len(c.prefix.Reservations)
	l.active = s
	return nil
}

func cloneSyntheticDNSLedger(l syntheticDNSLedger) syntheticDNSLedger {
	l.Reservations = slices.Clone(l.Reservations)
	for i := range l.Reservations {
		l.Reservations[i].CNAMEChain = slices.Clone(l.Reservations[i].CNAMEChain)
	}
	return l
}

func syntheticDNSLedgerPrefixEqual(a, b syntheticDNSLedger, count int) bool {
	if count < 0 || count > len(a.Reservations) || count > len(b.Reservations) || a.Schema != b.Schema || a.Owner != b.Owner {
		return false
	}
	return reflect.DeepEqual(a.Reservations[:count], b.Reservations[:count])
}

// Caller holds s.mu. A linked successor may append only through its original
// writeLedger owner. Matching disk suffixes alone never satisfy this proof.
func (s *NetworkPolicyDNSSyntheticResolver) closedLedgerMatches(disk syntheticDNSLedger) bool {
	if s.lineage == nil {
		return reflect.DeepEqual(disk, s.ledger)
	}
	l := s.lineage
	l.mu.Lock()
	defer l.mu.Unlock()
	return syntheticDNSLedgerPrefixEqual(disk, s.ledger, len(s.ledger.Reservations)) && reflect.DeepEqual(disk, l.ledger)
}
