package app

import (
	"context"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// A closed, private choice of original issuer. No DTO or arbitrary callback
// can fill this slot. Both-present and neither-present always refuse.
type xrayRuntimeScope struct {
	full   *ListScopeBinding
	finite *xrayFiniteScopeBinding
}

func (s xrayRuntimeScope) matches(a *App, store *config.Store) bool {
	if a == nil || store == nil || a.Store != store || (s.full == nil) == (s.finite == nil) {
		return false
	}
	if s.full != nil {
		return s.full.self == s.full && s.full.app == a && s.full.store == store
	}
	return s.finite.self == s.finite && s.finite.app == a && s.finite.store == store
}
func (r *XrayListRuntimeSource) scopeOwner() xrayRuntimeScope {
	if r == nil {
		return xrayRuntimeScope{}
	}
	return xrayRuntimeScope{r.scope, r.finiteScope}
}
func (e *managedXraySelectedTCPListExecution) scopeOwner() xrayRuntimeScope {
	if e == nil {
		return xrayRuntimeScope{}
	}
	return xrayRuntimeScope{e.scope, e.finiteScope}
}
func (s xrayRuntimeScope) original() bool {
	if (s.full == nil) == (s.finite == nil) {
		return false
	}
	if s.full != nil {
		return s.matches(s.full.app, s.full.store)
	}
	return s.matches(s.finite.app, s.finite.store)
}
func (s xrayRuntimeScope) use(c context.Context, action func(context.Context) error) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.use(c, action)
	}
	return s.finite.use(c, action)
}
func (s xrayRuntimeScope) Observe(c context.Context) (DefaultRouteSnapshot, error) {
	if !s.original() {
		return DefaultRouteSnapshot{}, ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.Observe(c)
	}
	return s.finite.Observe(c)
}
func (s xrayRuntimeScope) BindCompilation(c context.Context, compilation *DefaultRouteCompilation) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.BindCompilation(c, compilation)
	}
	return s.finite.BindCompilation(c, compilation)
}
func (s xrayRuntimeScope) ScopeCheck(c context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.ScopeCheck(c, plan)
	}
	return s.finite.ScopeCheck(c, plan)
}
func (s xrayRuntimeScope) cleanupScopeCheck(c context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.cleanupScopeCheck(c, plan)
	}
	return s.finite.cleanupScopeCheck(c, plan)
}
func (s xrayRuntimeScope) AcceptCommitted(c context.Context, after config.Config, started, finished time.Time) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.AcceptCommitted(c, after, started, finished)
	}
	return s.finite.AcceptCommitted(c, after, started, finished)
}
func (s xrayRuntimeScope) AcceptAutonomyCommitted(c context.Context, receipt *config.AutonomyRouteCommitReview) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.AcceptAutonomyCommitted(c, receipt)
	}
	return s.finite.AcceptAutonomyCommitted(c, receipt)
}
func (s xrayRuntimeScope) AcceptAutonomyRestored(c context.Context, receipt *config.AutonomyRouteCommitReview) error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.AcceptAutonomyRestored(c, receipt)
	}
	return s.finite.AcceptAutonomyRestored(c, receipt)
}
func (s xrayRuntimeScope) identity() netidentity.Identity {
	if !s.original() {
		return netidentity.Identity{}
	}
	if s.full != nil {
		return s.full.facts.Identity
	}
	return s.finite.facts.Identity
}
func (s xrayRuntimeScope) networkID() string {
	if !s.original() {
		return ""
	}
	if s.full != nil {
		return s.full.networkID
	}
	return s.finite.networkID
}
func (s xrayRuntimeScope) devices() []physicalscope.Device {
	if !s.original() {
		return nil
	}
	if s.full != nil {
		return s.full.facts.Devices
	}
	return s.finite.facts.Devices
}
func (s xrayRuntimeScope) segments() []physicalscope.Segment {
	if !s.original() {
		return nil
	}
	if s.full != nil {
		return s.full.facts.Segments
	}
	return s.finite.facts.Segments
}
func (s xrayRuntimeScope) hasPhysicalIssuer() bool {
	if !s.original() {
		return false
	}
	if s.full != nil {
		return s.full.originalPhysicalObserver != nil && s.full.originalPhysicalReview != nil
	}
	return s.finite.principal != nil
}
func (s xrayRuntimeScope) Close() error {
	if !s.original() {
		return ErrListScopeChanged
	}
	if s.full != nil {
		return s.full.Close()
	}
	return s.finite.Close()
}
func (e *managedXraySelectedTCPListExecution) reviewPrimary(c context.Context, ingress string, address netip.Addr) error {
	s := e.scopeOwner()
	if !s.hasPhysicalIssuer() || e.primary != nil || e.finitePrimary != nil {
		return ErrListScopeChanged
	}
	var err error
	if s.full != nil {
		e.primary, err = s.full.originalPhysicalObserver.ReviewPrimaryIPv4(c, s.full.originalPhysicalReview, ingress, address)
	} else {
		e.finitePrimary, err = s.finite.principal.ReviewPrimaryIPv4(c, ingress, address)
	}
	return err
}
func (e *managedXraySelectedTCPListExecution) primaryCurrent(c context.Context) error {
	return e.checkPrimary(c, false)
}
func (e *managedXraySelectedTCPListExecution) primaryCurrentRetained(c context.Context) error {
	return e.checkPrimary(c, true)
}
func (e *managedXraySelectedTCPListExecution) checkPrimary(c context.Context, retained bool) error {
	s := e.scopeOwner()
	if !s.original() || (e.primary == nil) == (e.finitePrimary == nil) {
		return ErrListScopeChanged
	}
	if s.full != nil {
		if e.primary == nil {
			return ErrListScopeChanged
		}
		if retained {
			return e.primary.CurrentRetained(c)
		}
		return e.primary.Current(c)
	}
	if e.finitePrimary == nil || !e.finitePrimary.MatchesPrincipal(s.finite.principal) {
		return ErrListScopeChanged
	}
	if retained {
		return e.finitePrimary.CurrentRetained(c)
	}
	return e.finitePrimary.Current(c)
}
