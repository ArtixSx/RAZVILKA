package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type syntheticSettlementCandidate struct {
	row  syntheticCTRow
	kind string // standby-shaped, capture-shaped, or unsupported; never owned
}

type syntheticSettlementObservation struct {
	mapping       dnscontrol.SyntheticDNSMappingObservation
	cacheDeadline time.Time
	first, second []syntheticSettlementCandidate
	comparison    string // unchanged or changed; two dumps are NOT atomic
	pending       string // always nonempty: no cache/capture/late-SYN completion grant
}

// Pre-issued, read-only finite owner. There is intentionally no Delete,
// Retire, reuse or completion method and no persisted-metadata constructor.
type syntheticSettlementReader struct {
	self       *syntheticSettlementReader
	binding    *SyntheticDNSExecutionBinding
	session    *scopedDNSSession
	mode       *scopedDNSSyntheticMode
	source     *dnscontrol.NetworkPolicyDNSSyntheticResolver
	retirement *dnscontrol.SyntheticDNSRetirementReview
	control    *operationgate.ControlEpochReview
	cleanup    *operationgate.ExclusiveCleanupReview
	frozen     dnscontrol.SyntheticDNSMappingObservation
	original   *dnscontrol.SyntheticDNSMapping
	capture    *DomainPolicyTCPCapture
	prepared   *DomainPolicyTCPCaptureMapping
	captureEnd *DomainPolicyTCPCaptureRetirement
	endpoint   netip.AddrPort
	read       func(context.Context) (syntheticCTImage, error) // private socket-free model seam
}

func (b *SyntheticDNSExecutionBinding) settlementReader(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, control *operationgate.ControlEpochReview, capture *DomainPolicyTCPCapture) (*syntheticSettlementReader, error) {
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	// Actual original mapping compiler validates the SAME source/client/plan.
	if _, err := SyntheticBaselineTransitionEffects(ctx, b.transport, b.domain, mapping); err != nil {
		return nil, err
	}
	session, err := b.originalSyntheticSession(control)
	if err != nil {
		return nil, err
	}
	retirement, err := mapping.ReviewRetirement(ctx, session.synthetic.source, b.dns, b.transport.DNS, control, b.root, b.transport.Definition)
	if err != nil {
		return nil, err
	}
	cleanup, err := control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	frozen, err := mapping.Observation(ctx)
	if err != nil {
		return nil, err
	}
	if capture == nil || !capture.matchesObservation(frozen) {
		return nil, ErrDomainPolicyTCPConsumer
	}
	captureEnd, err := capture.Retirement(ctx)
	if err != nil {
		return nil, err
	}
	capture.mu.Lock()
	prepared := capture.mappings[mapping]
	capture.mu.Unlock()
	if prepared == nil || prepared.source != mapping {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := prepared.Current(ctx); err != nil {
		return nil, err
	}
	endpoint, err := capture.Address()
	if err != nil || endpoint.String() != b.transport.CaptureEndpoint {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	r := &syntheticSettlementReader{binding: b, session: session, mode: session.synthetic, source: session.synthetic.source, retirement: retirement, control: control, cleanup: cleanup, frozen: frozen, original: mapping, capture: capture, prepared: prepared, captureEnd: captureEnd, endpoint: endpoint, read: readSyntheticConntrack}
	r.self = r
	if err := b.Current(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Cancellation/Stop permits only observation under the pre-issued ORIGINAL
// cleanup lease. The Manager scope must remain open until the read joins.
// The existing scope close and original operation release revoke this reader.
func (r *syntheticSettlementReader) observe(ctx context.Context) (observation syntheticSettlementObservation, err error) {
	if r == nil || r.self != r || r.binding == nil || r.binding.self != r.binding || r.retirement == nil || r.cleanup == nil || r.control == nil || r.read == nil || ctx == nil || ctx.Err() != nil {
		return observation, errSyntheticConntrack
	}
	if _, finite := ctx.Deadline(); !finite {
		return observation, errSyntheticConntrack
	}
	b, s := r.binding, r.binding.scope
	if s == nil || s.networkIdentity == nil {
		return observation, errSyntheticConntrack
	}
	checkLocal := func(c context.Context) error {
		return b.checkSettlementOwner(c)
	}
	readImage := func(c context.Context) (syntheticCTImage, error) {
		var image syntheticCTImage
		if err := checkLocal(c); err != nil {
			return image, err
		}
		// Provider brackets the socket in the SAME actual thread namespace.
		// Do not reenter provider.check inside its callback.
		err := s.networkIdentity.use(c, func(held context.Context) error {
			if err := checkLocal(held); err != nil {
				return err
			}
			if err := r.control.CurrentForCleanup(held); err != nil {
				return err
			}
			var err error
			image, err = r.read(held)
			return errors.Join(err, r.control.CurrentForCleanup(held), checkLocal(held))
		})
		return image, errors.Join(err, checkLocal(c))
	}
	err = b.withSettlementCurrent(ctx, r.control, r.cleanup, func() error {
		if err := checkLocal(ctx); err != nil {
			return err
		}
		if err := r.joinedDNS(); err != nil {
			return err
		}
		row, err := r.retirement.ClosedObservation(ctx)
		if err != nil || !syntheticSettlementCoordinatesEqual(row, r.frozen) {
			return errors.Join(errSyntheticConntrack, err)
		}
		endpoint, err := r.captureEndpoint(ctx)
		if err != nil {
			return err
		}
		firstCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		first, err := readImage(firstCtx)
		cancel()
		if err != nil {
			return err
		}
		secondCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		second, err := readImage(secondCtx)
		cancel()
		if err != nil {
			return err
		}
		after, err := r.retirement.ClosedObservation(ctx)
		if err != nil || !reflect.DeepEqual(row, after) {
			return errors.Join(errSyntheticConntrack, err)
		}
		afterEndpoint, endpointErr := r.captureEndpoint(ctx)
		if endpointErr != nil || afterEndpoint != endpoint {
			return errors.Join(errSyntheticConntrack, endpointErr)
		}
		observation, err = compareSyntheticSettlement(first, second, row, endpoint)
		return errors.Join(err, r.control.CurrentForCleanup(ctx), r.joinedDNS(), checkLocal(ctx))
	})
	if err != nil {
		return syntheticSettlementObservation{}, err
	}
	return observation, nil
}

// The original process-local publication registry provides source identity;
// the adapter's mutation mutex is never taken inside a DNS request callback.
func (b *SyntheticDNSExecutionBinding) originalSyntheticSession(control *operationgate.ControlEpochReview) (*scopedDNSSession, error) {
	if b == nil || b.self != b || control == nil {
		return nil, ErrDomainTransportRuntime
	}
	scopedDNSInactiveLifecycle.Lock()
	defer scopedDNSInactiveLifecycle.Unlock()
	root := scopedDNSInactiveLifecycle.roots[b.root]
	if root == nil || root.pending != 0 {
		return nil, ErrDomainTransportRuntime
	}
	var found *scopedDNSSession
	for s := range root.sessions {
		if s.synthetic == nil || s.synthetic.binding != b {
			continue
		}
		if found != nil || s.synthetic.control != control || s.synthetic.source == nil {
			return nil, ErrDomainTransportRuntime
		}
		found = s
	}
	if found == nil {
		return nil, ErrDomainTransportRuntime
	}
	return found, nil
}

func (r *syntheticSettlementReader) joinedDNS() error {
	if r == nil || r.self != r || r.session == nil || r.binding == nil || r.mode == nil || r.session.synthetic != r.mode || r.source == nil || r.mode.source != r.source {
		return ErrDomainTransportRuntime
	}
	s, err := r.binding.originalSyntheticSession(r.control)
	if err != nil || s != r.session {
		return errors.Join(ErrDomainTransportRuntime, err)
	}
	return r.session.inactiveJoined()
}

func (r *syntheticSettlementReader) captureEndpoint(ctx context.Context) (netip.AddrPort, error) {
	if r == nil || r.self != r || r.original == nil || r.capture == nil || r.capture.self != r.capture || r.prepared == nil || r.prepared.self != r.prepared || r.prepared.capture != r.capture || r.prepared.source != r.original || r.captureEnd == nil || r.captureEnd.capture != r.capture || !syntheticSettlementCoordinatesEqual(r.prepared.observation, r.frozen) {
		return netip.AddrPort{}, ErrDomainPolicyTCPConsumer
	}
	endpoint, err := r.captureEnd.Endpoint(ctx)
	if err != nil || endpoint != r.endpoint {
		return netip.AddrPort{}, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	c := r.capture
	c.mu.Lock()
	original := c.mappings[r.original]
	c.mu.Unlock()
	if original != r.prepared {
		return netip.AddrPort{}, ErrDomainPolicyTCPConsumer
	}
	r.prepared.mu.Lock()
	closed := r.prepared.closed
	r.prepared.mu.Unlock()
	if !closed {
		return netip.AddrPort{}, ErrDomainPolicyTCPCaptureRetirementPending
	}
	for _, joined := range []<-chan struct{}{r.prepared.closeDone, r.prepared.watchDone} {
		select {
		case <-joined:
		default:
			return netip.AddrPort{}, ErrDomainPolicyTCPCaptureRetirementPending
		}
	}
	return endpoint, nil
}

// Shared by the actual observer and socket-free original-owner models. The
// callback receives no forward context or effect grant. Scope.close joins it.
func (b *SyntheticDNSExecutionBinding) withSettlementCurrent(ctx context.Context, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, use func() error) error {
	if b == nil || b.self != b || b.scope == nil || b.scope.networkIdentity == nil || control == nil || cleanup == nil || use == nil || ctx == nil || ctx.Err() != nil {
		return errSyntheticConntrack
	}
	s := b.scope
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	checkLocal := func() error {
		return b.checkSettlementOwner(ctx)
	}
	return cleanup.WithCurrent(ctx, func() error {
		if err := checkLocal(); err != nil {
			return err
		}
		if err := control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		if err := s.networkIdentity.check(ctx); err != nil {
			return err
		}
		err := use()
		return errors.Join(err, control.CurrentForCleanup(ctx), s.networkIdentity.check(ctx), checkLocal())
	})
}

func (b *SyntheticDNSExecutionBinding) checkSettlementOwner(ctx context.Context) error {
	s := b.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manager == nil || s.networkIdentity == nil || s.owned == nil || b.adapter == nil || s.adapterOwner != b.adapter || b.adapter.DNS != b.dns || b.adapter.StateRoot != b.root || b.adapter.InactivityIdentity != s.networkIdentity.provider || !reflect.DeepEqual(s.plan, b.plan) {
		return ErrDomainTransportRuntime
	}
	opened, err := s.owned.RootInfo()
	if err != nil || !os.SameFile(s.anchor, opened) {
		return errors.Join(ErrDomainTransportRuntime, err)
	}
	return s.checkOriginalOwner(ctx, nil, false, false)
}

func syntheticSettlementCoordinatesEqual(a, b dnscontrol.SyntheticDNSMappingObservation) bool {
	a.PossiblyIssued, b.PossiblyIssued = false, false
	a.LastPossiblyIssuedAt, b.LastPossiblyIssuedAt = time.Time{}, time.Time{}
	a.LastPossiblyIssuedTTLBound, b.LastPossiblyIssuedTTLBound = 0, 0
	return reflect.DeepEqual(a, b)
}

func compareSyntheticSettlement(first, second syntheticCTImage, mapping dnscontrol.SyntheticDNSMappingObservation, capture netip.AddrPort) (syntheticSettlementObservation, error) {
	var o syntheticSettlementObservation
	if !first.complete || !second.complete || !mapping.Client.Is4() || !mapping.Synthetic.Is4() || !mapping.RealIPv4.Is4() || !capture.IsValid() {
		return o, errSyntheticConntrack
	}
	classify := func(image syntheticCTImage) []syntheticSettlementCandidate {
		var out []syntheticSettlementCandidate
		for _, row := range image.rows {
			// Include OTHER clients and reply-only synthetic references: they
			// must not disappear merely because the reviewed client differs.
			if row.Original.Source != mapping.Synthetic && row.Original.Destination != mapping.Synthetic && row.Reply.Source != mapping.Synthetic && row.Reply.Destination != mapping.Synthetic && (!row.MasterPresent || row.Master.Source != mapping.Synthetic && row.Master.Destination != mapping.Synthetic) {
				continue
			}
			kind := "unsupported"
			const unsafeStatus = uint32(1 | 0x40 | 0x200 | 0x800 | 0x1000 | 0x2000 | 0x4000 | 0x8000)
			plainReply := row.Reply.Destination == mapping.Client && row.Reply.DestinationPort == row.Original.SourcePort
			snat := row.Status&(0x10|0x80) == (0x10|0x80) && row.Reply.Destination.IsGlobalUnicast()
			if row.Original.Source == mapping.Client && row.Original.Destination == mapping.Synthetic && row.Original.Protocol == 6 && row.Reply.Protocol == 6 && row.Original.SourcePort != 0 && (row.Original.DestinationPort == 80 || row.Original.DestinationPort == 443) && row.Reply.DestinationPort != 0 && (plainReply || snat) && row.Zone == 0 && row.Original.Zone == 0 && row.Reply.Zone == 0 && row.MarkPresent && !row.Unsafe && row.Status&unsafeStatus == 0 && row.Status&(8|0x20|0x100) == (8|0x20|0x100) {
				// Preserve observed reply.dst, including firmware SNAT. A
				// reciprocal NAT-shaped tuple is still NOT flow ownership.
				if row.Reply.Source == mapping.RealIPv4 && row.Reply.SourcePort == row.Original.DestinationPort {
					kind = "standby-shaped"
				}
				if row.Reply.Source == capture.Addr() && row.Reply.SourcePort == capture.Port() {
					kind = "capture-shaped"
				}
			}
			out = append(out, syntheticSettlementCandidate{row: row, kind: kind})
		}
		slices.SortFunc(out, func(a, b syntheticSettlementCandidate) int {
			if a.row.ID < b.row.ID {
				return -1
			}
			if a.row.ID > b.row.ID {
				return 1
			}
			return 0
		})
		return out
	}
	o.mapping = mapping
	o.mapping.CNAMEChain = slices.Clone(mapping.CNAMEChain)
	o.first, o.second = classify(first), classify(second)
	o.comparison = "changed"
	if slices.Equal(o.first, o.second) {
		o.comparison = "unchanged"
	}
	if mapping.PossiblyIssued {
		o.cacheDeadline = mapping.LastPossiblyIssuedAt.Add(time.Duration(mapping.LastPossiblyIssuedTTLBound) * time.Second)
	}
	o.pending = "client cache, late SYN and address reuse quiescence unproved; CT ID/tuple attribution to original accepted flow and ABA absence unproved"
	return o, nil
}
