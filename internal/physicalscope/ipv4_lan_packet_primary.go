package physicalscope

import (
	"context"
	"net/netip"
)

// IPv4LANPacketPrimaryReview ties the listener's address to the original
// Home packet scope. A membership change does not change the listener owner.
type IPv4LANPacketPrimaryReview struct {
	self    *IPv4LANPacketPrimaryReview
	scope   *IPv4LANPacketScope
	ingress string
	address netip.Addr
	// Protected by scope.mu.
	row     primaryIPv4Row
	issued  bool
	invalid bool
}

func (*IPv4LANPacketPrimaryReview) String() string   { return "[original Home primary IPv4 review]" }
func (*IPv4LANPacketPrimaryReview) GoString() string { return "[original Home primary IPv4 review]" }

func (p *IPv4LANPacketScope) ReviewPrimaryIPv4(ctx context.Context, ingress string, address netip.Addr) (*IPv4LANPacketPrimaryReview, error) {
	if p == nil || p.self != p || !interfaceName.MatchString(ingress) || !address.Is4() || !address.IsGlobalUnicast() {
		return nil, at("packet.primary.request", nil)
	}
	r := &IPv4LANPacketPrimaryReview{scope: p, ingress: ingress, address: address}
	r.self = r
	if err := r.current(ctx, false); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *IPv4LANPacketPrimaryReview) MatchesScope(p *IPv4LANPacketScope) bool {
	return r != nil && r.self == r && p != nil && r.scope == p && p.self == p
}

func (r *IPv4LANPacketPrimaryReview) MatchesBinding(p *IPv4LANPacketScope, ingress string, address netip.Addr) bool {
	return r.MatchesScope(p) && r.ingress == ingress && r.address == address
}

func (r *IPv4LANPacketPrimaryReview) Current(ctx context.Context) error {
	return r.current(ctx, false)
}

func (r *IPv4LANPacketPrimaryReview) CurrentRetained(ctx context.Context) error {
	return r.current(ctx, true)
}

func (r *IPv4LANPacketPrimaryReview) current(ctx context.Context, retained bool) error {
	if r == nil || !r.MatchesScope(r.scope) {
		return at("packet.primary.original", nil)
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	p := r.scope
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready(retained) || r.invalid || retained && !r.issued {
		return at("packet.primary.unavailable", nil)
	}
	home := p.topology.home
	if home.Interface != r.ingress || home.IfIndex <= 0 {
		return at("packet.primary.ingress", nil)
	}
	var first primaryIPv4Row
	passes := 0
	var observationErr error
	err = p.currentLocked(c, retained, func(frames []message) {
		passes++
		if observationErr != nil {
			return
		}
		// Packet topology and these raw rows come from the same complete
		// RTM_GETADDR dump inside both original identity/fence bookends.
		var ipv4 []message
		for _, frame := range frames {
			if len(frame.data) == 0 || frame.data[0] != 10 && frame.data[0] != 2 {
				observationErr = ErrUnknown
				return
			}
			if frame.data[0] == 2 {
				ipv4 = append(ipv4, frame)
			}
		}
		row, e := selectPrimaryIPv4(ipv4, home.IfIndex, r.ingress, r.address)
		if e != nil || !lanPrefix(netip.PrefixFrom(r.address, int(row.prefix)).Masked()) {
			observationErr = ErrUnknown
			return
		}
		row.preferred, row.valid = 0, 0
		if passes == 1 {
			first = row
		} else if first != row {
			observationErr = ErrUnknown
		}
	})
	if observationErr != nil || passes > 0 && r.issued && first != r.row {
		r.invalid = true
		return at("packet.primary.changed", observationErr)
	}
	if err != nil {
		return err
	}
	if passes != 2 || c.Err() != nil {
		return at("packet.primary.incomplete", c.Err())
	}
	r.row, r.issued = first, true
	return nil
}
