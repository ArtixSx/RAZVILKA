package physicalscope

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// FiniteIPv4PacketPrincipal owns one original sender attachment. It proves
// neither complete LAN coverage nor that the sender is a terminal/non-router.
// Its hidden Review reuses capture/join mechanics and cannot escape as Review.
type FiniteIPv4PacketPrincipal struct {
	self     *FiniteIPv4PacketPrincipal
	observer *Observer
	review   *Review
}

// FiniteIPv4PacketObservation is detached compilation data, never a full
// Snapshot or permission. UNKNOWN router facts retain their original identity
// key and absence of MAC; they are not clients or known infrastructure MACs.
type FiniteIPv4PacketObservation struct {
	ReviewID         string
	Identity         netidentity.Identity
	Selection        Selection
	Segments         []Segment
	Devices          []Device
	UnresolvedRouter []FiniteIPv4UnresolvedRouter
}

type FiniteIPv4UnresolvedRouter struct {
	Interface string
	IfIndex   int
	Address   string
	State     uint16
	Flags     uint8
	Type      uint8
}

func (*FiniteIPv4PacketPrincipal) String() string   { return "[original finite IPv4 packet principal]" }
func (*FiniteIPv4PacketPrincipal) GoString() string { return "[original finite IPv4 packet principal]" }

// The caller supplies only current selected intent. Actual protected stock NDM,
// complete kernel reads and original NI/fence bookends remain source-owned.
func NewReviewedStockNC1812FiniteIPv4PacketPrincipal(ctx context.Context, provider *netidentity.Provider, selection SelectionReader) (*FiniteIPv4PacketPrincipal, error) {
	o := newObserver(provider, selection, true)
	o.source = platformFiniteIPv4Source(provider)
	return newFiniteIPv4PacketPrincipal(ctx, o)
}

// Private source seam for explicitly modeled physics, not a public factory.
func newFiniteIPv4PacketPrincipal(ctx context.Context, o *Observer) (*FiniteIPv4PacketPrincipal, error) {
	if o == nil || !o.ready() || o.finite != nil {
		return nil, at("finite.dependencies", nil)
	}
	p := &FiniteIPv4PacketPrincipal{observer: o}
	p.self, o.finite = p, p
	read := o.selection
	o.selection = func(c context.Context) (Selection, error) {
		s, err := read(c)
		if err != nil {
			return Selection{}, err
		}
		if err := finiteIPv4Intent(s); err != nil {
			return Selection{}, err
		}
		return s, nil
	}
	r, err := o.observe(ctx)
	if err != nil {
		return nil, err
	}
	p.review = r
	if err := validateFiniteIPv4Snapshot(r.state.snapshot); err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return p, nil
}

func finiteIPv4Intent(s Selection) error {
	if s.Revision == 0 || s.PolicyRevision == 0 || len(s.SegmentIDs) != 1 || s.HomeSegmentID != "" || len(s.GuestSegmentIDs) != 0 ||
		s.SelectedDevices == nil || len(s.SelectedDevices.DeviceIDs) != 1 || slices.Contains(s.SelectedDevices.ExcludedDeviceIDs, s.SelectedDevices.DeviceIDs[0]) {
		return at("finite.intent", nil)
	}
	_, err := canonicalSelection(s)
	return err
}

func validateFiniteIPv4Snapshot(s Snapshot) error {
	if finiteIPv4Intent(s.Selection) != nil || s.Identity.Validate() != nil || s.Identity.Kind != netidentity.ReviewedSingleInitNet ||
		s.ReviewID == "" || len(s.Segments) != 1 || validateSelectedDevices(s.Selection.SelectedDevices, s.Devices) != nil {
		return at("finite.binding", nil)
	}
	chosen := s.Selection.SelectedDevices.DeviceIDs[0]
	count := 0
	for _, d := range s.Devices {
		if d.ID != chosen {
			continue
		}
		if d.Interface != s.Segments[0].Interface || d.IfIndex != s.Segments[0].IfIndex {
			return at("finite.ingress", nil)
		}
		for _, raw := range d.Addresses {
			a, err := netip.ParseAddr(raw)
			if err != nil {
				return at("finite.address", err)
			}
			if a.Is4() && a.IsGlobalUnicast() {
				count++
			}
		}
	}
	if count != 1 {
		return at("finite.ipv4-count", nil)
	}
	return nil
}

func (p *FiniteIPv4PacketPrincipal) original() bool {
	return p != nil && p.self == p && p.observer != nil && p.observer.finite == p && p.review != nil &&
		p.review.state != nil && p.review.state.self == p.review && p.review.state.issuer == p.observer
}

func (p *FiniteIPv4PacketPrincipal) Current(ctx context.Context) error {
	if !p.original() {
		return at("finite.original", nil)
	}
	return p.observer.verify(ctx, p.review)
}

// CurrentRetained never restores selection/forward admission; the App must
// separately retain its original operation and cleanup/retirement receipts.
func (p *FiniteIPv4PacketPrincipal) CurrentRetained(ctx context.Context) error {
	if !p.original() {
		return at("finite.retained.original", nil)
	}
	return p.observer.verifyRetainedIncarnation(ctx, p.review)
}

func (p *FiniteIPv4PacketPrincipal) Observation() FiniteIPv4PacketObservation {
	if !p.original() {
		return FiniteIPv4PacketObservation{}
	}
	s := p.review.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return FiniteIPv4PacketObservation{}
	}
	f := cloneSnapshot(s.snapshot)
	out := FiniteIPv4PacketObservation{ReviewID: f.ReviewID, Identity: f.Identity, Selection: f.Selection, Segments: f.Segments, Devices: f.Devices}
	for _, segment := range f.Segments {
		for _, n := range segment.unresolvedRouters {
			out.UnresolvedRouter = append(out.UnresolvedRouter, FiniteIPv4UnresolvedRouter{segment.Interface, n.index, n.address.String(), n.state, n.flags, n.kind})
		}
	}
	return out
}

func (p *FiniteIPv4PacketPrincipal) Close() error {
	if p == nil {
		return nil
	}
	if !p.original() {
		return at("finite.close.original", nil)
	}
	return p.review.Close()
}

// FiniteIPv4PrimaryReview belongs to this SAME finite issuer; it cannot be used
// as the full Observer's PrimaryIPv4Review. Native address flags, residence,
// prefix and incarnation checks use exactly the existing primary reader.
type FiniteIPv4PrimaryReview struct {
	self      *FiniteIPv4PrimaryReview
	principal *FiniteIPv4PacketPrincipal
	primary   *PrimaryIPv4Review
}

func (*FiniteIPv4PrimaryReview) String() string   { return "[original finite IPv4 primary review]" }
func (*FiniteIPv4PrimaryReview) GoString() string { return "[original finite IPv4 primary review]" }

func (p *FiniteIPv4PacketPrincipal) ReviewPrimaryIPv4(ctx context.Context, ingress string, address netip.Addr) (*FiniteIPv4PrimaryReview, error) {
	return p.reviewPrimaryIPv4(ctx, ingress, address, readPrimaryIPv4Dump)
}

func (p *FiniteIPv4PacketPrincipal) reviewPrimaryIPv4(ctx context.Context, ingress string, address netip.Addr, read func(context.Context) ([]message, error)) (*FiniteIPv4PrimaryReview, error) {
	if !p.original() {
		return nil, at("finite.primary.original", nil)
	}
	if err := p.Current(ctx); err != nil {
		return nil, boundary("finite.primary.current", err)
	}
	primary, err := p.observer.reviewPrimaryIPv4(ctx, p.review, ingress, address, read)
	if err != nil {
		return nil, err
	}
	r := &FiniteIPv4PrimaryReview{principal: p, primary: primary}
	r.self = r
	return r, nil
}

func (p *FiniteIPv4PrimaryReview) original() bool {
	return p != nil && p.self == p && p.principal.original() && p.primary != nil && p.primary.state != nil &&
		p.primary.state.self == p.primary && p.primary.state.original == p.principal.review && p.primary.state.observer == p.principal.observer
}

// MatchesPrincipal compares original typed owners, never observation data.
func (p *FiniteIPv4PrimaryReview) MatchesPrincipal(principal *FiniteIPv4PacketPrincipal) bool {
	return p.original() && p.principal == principal
}

func (p *FiniteIPv4PrimaryReview) Current(ctx context.Context) error {
	if !p.original() {
		return at("finite.primary.original", nil)
	}
	return p.primary.current(ctx, false)
}

func (p *FiniteIPv4PrimaryReview) CurrentRetained(ctx context.Context) error {
	if !p.original() {
		return at("finite.primary.retained.original", nil)
	}
	return p.primary.currentRetained(ctx)
}
