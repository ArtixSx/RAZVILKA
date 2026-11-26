package dataplane

import (
	"context"
	"errors"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/components"
)

// Private comparison role, issued only by the original running child. This is
// neither a serialized socket exception nor a callback supplied by a caller.
type mihomoLiveSOCKSUDPListener struct {
	self     *mihomoLiveSOCKSUDPListener
	owner    *mihomoLiveResource
	child    *components.MihomoLiveProcess
	source   *components.MihomoLiveSource
	profile  components.MihomoLiveProfileReference
	pid      int
	readView *components.MihomoLiveObservation
}

func (r *mihomoLiveResource) reviewSOCKSUDPListener(ctx context.Context) (*mihomoLiveSOCKSUDPListener, error) {
	return r.reviewSOCKSUDPListenerRead(ctx, nil)
}

func (r *mihomoLiveResource) reviewSOCKSUDPListenerRead(ctx context.Context, view *components.MihomoLiveObservation) (*mihomoLiveSOCKSUDPListener, error) {
	if r == nil || r.self != r {
		return nil, ErrNodeTransitUnavailable
	}
	r.mu.Lock()
	child, source := r.child, r.source
	r.mu.Unlock()
	if child == nil || source == nil {
		return nil, ErrNodeTransitUnavailable
	}
	role := &mihomoLiveSOCKSUDPListener{owner: r, child: child, source: source, profile: r.definition.Profile, pid: child.PID(), readView: view}
	role.self = role
	if err := role.current(ctx, role.pid); err != nil {
		return nil, err
	}
	return role, nil
}

func (role *mihomoLiveSOCKSUDPListener) current(ctx context.Context, pid int) error {
	if role == nil || role.self != role || role.owner == nil || role.child == nil || role.source == nil || role.pid <= 1 || role.pid != pid || role.child.PID() != pid || xraySelectedTCPFinite(ctx) != nil {
		return ErrNodeTransitUnavailable
	}
	if !role.sameOwner() {
		return ErrNodeTransitUnavailable
	}
	r := role.owner
	if !role.source.OwnedBy(r.adapter.components) || role.source.Reference() != r.definition.Source || role.source.Reference().Version != components.ReviewedMihomoVersion || role.profile != r.definition.Profile || role.profile.SOCKSPort < 1024 || role.profile.SOCKSPort > 65535 {
		return ErrNodeTransitUnavailable
	}
	if role.readView != nil {
		if !role.readView.BoundTo(role.child, role.source) {
			return ErrNodeTransitUnavailable
		}
		profile, err := role.readView.ProfileReference(ctx)
		if err != nil || profile != role.profile {
			return errors.Join(ErrNodeTransitUnavailable, err)
		}
		return ctx.Err()
	}
	profile, err := role.child.ProfileReference(ctx)
	if err != nil || profile != role.profile {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	return role.source.Current(ctx)
}

// Pointer comparison only; the actual child/profile/installed-source reads in
// current remain mandatory even after this structural check succeeds.
func (role *mihomoLiveSOCKSUDPListener) sameOwner() bool {
	if role == nil || role.self != role || role.owner == nil || role.child == nil || role.source == nil {
		return false
	}
	r := role.owner
	if r.self != r || r.scope == nil || r.scope.mihomoLive != r || r.adapter == nil || !r.adapter.RegisteredWith(r.scope.manager) {
		return false
	}
	r.mu.Lock()
	same := r.child == role.child && r.source == role.source && !r.closed && !r.retired
	r.mu.Unlock()
	return same
}

func (role *mihomoLiveSOCKSUDPListener) matches(kind string, socket nodeRouterBackendSocket, source, pin netip.Addr, alreadyMatched bool) bool {
	if role == nil || role.self != role || alreadyMatched || role.profile.SOCKSPort < 1024 || role.profile.SOCKSPort > 65535 || source.IsLoopback() || !source.Is4() || !pin.Is4() {
		return false
	}
	return kind == "udp" && socket.state == "07" && socket.inode != "" &&
		socket.local == netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(role.profile.SOCKSPort)) &&
		socket.remote == netip.AddrPortFrom(netip.IPv4Unspecified(), 0) && socket.local.Addr() != source && socket.remote.Addr() != pin
}
