package dnscontrol

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// An original, pre-issued read-only view. Persisted reservations and copied
// observations cannot issue it. It grants neither effects nor address reuse.
type SyntheticDNSRetirementReview struct {
	self    *SyntheticDNSRetirementReview
	mapping *SyntheticDNSMapping
	source  *NetworkPolicyDNSSyntheticResolver
	control *operationgate.ControlEpochReview
	cleanup *operationgate.ExclusiveCleanupReview
	root    string
	anchor  os.FileInfo
	frozen  SyntheticDNSMappingObservation
}

func (*SyntheticDNSRetirementReview) String() string {
	return "[original synthetic DNS retirement observation]"
}
func (*SyntheticDNSRetirementReview) GoString() string {
	return "[original synthetic DNS retirement observation]"
}

// ReviewRetirement must run while the original mapping is live, inside the
// SAME still-held exclusive operation. It does not detach that operation.
func (m *SyntheticDNSMapping) ReviewRetirement(ctx context.Context, originalSource *NetworkPolicyDNSSyntheticResolver, manager *Manager, plan *NetworkPolicyDNSPlan, control *operationgate.ControlEpochReview, root string, definition SyntheticDNSDefinition) (*SyntheticDNSRetirementReview, error) {
	if m == nil || m.self != m || m.source == nil || m.source != originalSource || plan == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSyntheticDNSMapping
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, ErrSyntheticDNSMapping
	}
	s := m.source
	if err := s.CheckAdapterBinding(ctx, manager, plan, control, root, definition); err != nil {
		return nil, err
	}
	observation, err := m.Observation(ctx)
	if err != nil {
		return nil, err
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	r := &SyntheticDNSRetirementReview{mapping: m, source: s, control: control, cleanup: cleanup, root: root, anchor: s.anchor, frozen: observation}
	r.self = r
	if err := m.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// ClosedObservation reads the final durable publication metadata only after
// the original source Close has joined its actual requests and closed its fd.
// The caller supplies a fresh finite cleanup context; the ORIGINAL operation
// must remain held. Expiry and Stop do not recreate a forward mapping.
func (r *SyntheticDNSRetirementReview) ClosedObservation(ctx context.Context) (SyntheticDNSMappingObservation, error) {
	var observation SyntheticDNSMappingObservation
	if r == nil || r.self != r || r.cleanup == nil || r.control == nil {
		return observation, ErrSyntheticDNSMapping
	}
	err := r.cleanup.WithCurrent(ctx, func() error {
		if err := r.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		var err error
		observation, err = r.readClosed(ctx)
		return errors.Join(err, r.control.CurrentForCleanup(ctx))
	})
	if err != nil {
		return SyntheticDNSMappingObservation{}, errors.Join(ErrSyntheticDNSMapping, err)
	}
	return observation, nil
}

func (r *SyntheticDNSRetirementReview) readClosed(ctx context.Context) (observation SyntheticDNSMappingObservation, resultErr error) {
	s, m := r.source, r.mapping
	if ctx.Err() != nil || s == nil || s.self != s || m == nil || m.self != m || m.source != s || s.control != r.control || s.root != r.root || !s.closed.Load() {
		return SyntheticDNSMappingObservation{}, ErrSyntheticDNSMapping
	}
	select {
	case <-s.closeDone:
	default:
		return SyntheticDNSMappingObservation{}, ErrSyntheticDNSTransitionPending
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr != nil || m.index < 0 || m.index >= len(s.ledger.Reservations) || m.answer == nil || m.answer.resolver != s.resolver {
		return SyntheticDNSMappingObservation{}, ErrSyntheticDNSMapping
	}
	row := s.ledger.Reservations[m.index]
	if s.mappings[row.Synthetic] != m || !syntheticDNSRetirementCoordinatesEqual(row, r.frozen) || r.frozen.PossiblyIssued && (!row.PossiblyIssued || row.LastPossiblyIssuedAt.Before(r.frozen.LastPossiblyIssuedAt)) {
		return SyntheticDNSMappingObservation{}, ErrSyntheticDNSMapping
	}
	before, err := os.Lstat(r.root)
	if err != nil || !os.SameFile(r.anchor, before) || !os.SameFile(s.anchor, before) || syntheticDNSProtectedRoot(r.root) != nil {
		return SyntheticDNSMappingObservation{}, errors.Join(ErrSyntheticDNSMapping, err)
	}
	owned, err := ownedfs.Open(r.root)
	if err != nil {
		return SyntheticDNSMappingObservation{}, err
	}
	defer func() {
		if err := owned.Close(); err != nil {
			observation = SyntheticDNSMappingObservation{}
			resultErr = errors.Join(ErrSyntheticDNSMapping, resultErr, err)
		}
	}()
	opened, err := owned.RootInfo()
	if err != nil || !os.SameFile(r.anchor, opened) {
		return SyntheticDNSMappingObservation{}, errors.Join(ErrSyntheticDNSMapping, err)
	}
	info, err := owned.Stat(syntheticDNSLedgerName)
	if err != nil || !syntheticDNSProtectedFile(info) {
		return SyntheticDNSMappingObservation{}, errors.Join(ErrSyntheticDNSMapping, err)
	}
	wire, err := owned.ReadLimited(syntheticDNSLedgerName, 1<<20)
	disk, decodeErr := decodeSyntheticDNSLedger(wire)
	after, statErr := os.Lstat(r.root)
	if err != nil || decodeErr != nil || statErr != nil || !os.SameFile(r.anchor, after) || syntheticDNSProtectedRoot(r.root) != nil || !reflect.DeepEqual(disk, s.ledger) || ctx.Err() != nil {
		return SyntheticDNSMappingObservation{}, errors.Join(ErrSyntheticDNSMapping, err, decodeErr, statErr, ctx.Err())
	}
	row.CNAMEChain = slices.Clone(row.CNAMEChain)
	return row, nil
}

func syntheticDNSRetirementCoordinatesEqual(a, b SyntheticDNSMappingObservation) bool {
	a.PossiblyIssued, b.PossiblyIssued = false, false
	a.LastPossiblyIssuedAt, b.LastPossiblyIssuedAt = time.Time{}, time.Time{}
	a.LastPossiblyIssuedTTLBound, b.LastPossiblyIssuedTTLBound = 0, 0
	return reflect.DeepEqual(a, b)
}

// CacheDeadline is a comparison bound only. Neither reaching it nor observing
// a closed source proves client cache, late SYN or in-flight reply quiescence.
func (r *SyntheticDNSRetirementReview) CacheDeadline(ctx context.Context) (time.Time, error) {
	row, err := r.ClosedObservation(ctx)
	if err != nil || !row.PossiblyIssued {
		return time.Time{}, err
	}
	return row.LastPossiblyIssuedAt.Add(time.Duration(row.LastPossiblyIssuedTTLBound) * time.Second), nil
}
