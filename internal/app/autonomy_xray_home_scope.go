package app

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

type autonomyHomeScopeKey struct{}
type autonomyHomeReadKey struct{}
type homeReserveHintKey struct{}

type homeQueueHintsKey struct{}

type homeQueueHint struct {
	service               autonomy.Service
	node, version         string
	checkedAt, validUntil time.Time
}

// Snapshot while the coordinator already owns the document; no worker or
// catalogue lock is borrowed across the later candidate search.
func homeQueueHints(doc autonomyDocument, chosen string, configRevision uint64, now time.Time) []homeQueueHint {
	var hints []homeQueueHint
	for id, state := range doc.Runtime {
		service := doc.Services[id]
		if id == chosen || !service.Enabled || service.Removing || !service.AllLAN || service.ExpectedRoute != "auto" ||
			len(service.Sources) != 0 || state.State != homeServiceCheckedState || state.Search == nil || len(state.Reserves) != 1 ||
			state.ReserveConfigRevision != configRevision || state.ReserveCheckedAt.IsZero() || now.Before(state.ReserveCheckedAt) || !now.Before(state.ReserveValidUntil) {
			continue
		}
		service.Sources = slices.Clone(service.Sources)
		hints = append(hints, homeQueueHint{service: service, node: state.Reserves[0], version: state.Search.Version, checkedAt: state.ReserveCheckedAt, validUntil: state.ReserveValidUntil})
	}
	return hints
}

type homeReserveHint struct {
	version, node string
	checkedAt     time.Time
}

// A diagnostic reserve is public only while that exact observation is current.
// Keep its identity privately for the next admitted search to revalidate.
func withdrawHomeReserve(r *autonomy.Runtime) homeReserveHint {
	var hint homeReserveHint
	if r.State != homeServiceCheckedState {
		return hint
	}
	if r.Search != nil && len(r.Reserves) == 1 && !r.ReserveCheckedAt.IsZero() {
		hint = homeReserveHint{r.Search.Version, r.Reserves[0], r.ReserveCheckedAt}
	}
	r.Reserves, r.ReserveCheckedAt = nil, time.Time{}
	r.ReserveConfigRevision, r.ReserveValidUntil = 0, time.Time{}
	return hint
}

func pendingHomeReserve(r autonomy.Runtime) autonomy.Runtime {
	withdrawHomeReserve(&r)
	r.State, r.Message = "pending", "Ожидается повторная проверка резерва."
	return r
}

// Carries the same live Home packet observer from the service check to Apply.
// Only a successful loan transfers Close to the execution (including rollback).
type autonomyXrayHomeRound struct {
	self             *autonomyXrayHomeRound
	mu               sync.Mutex
	app              *App
	store            *config.Store
	original         context.Context
	spec             autonomy.Service
	policy           *config.NetworkPolicy
	consent          *config.DefaultRouteConsent
	provider         *netidentity.Provider
	binding          *xrayHomeScopeBinding
	closed, borrowed bool
	webCheckOnly     bool
}

type autonomyHomeRead struct {
	binding *xrayHomeScopeBinding
	active  atomic.Bool
}

// Called inside the binding's before/after-read bracket. Nested resource checks
// in the runtime source must use that bracket without re-entering its mutex.
func withAutonomyHomeScopeRead(ctx context.Context, b *xrayHomeScopeBinding, action func(context.Context) error) error {
	mark := &autonomyHomeRead{binding: b}
	mark.active.Store(true)
	defer mark.active.Store(false)
	return action(context.WithValue(ctx, autonomyHomeReadKey{}, mark))
}

func (a *App) autonomyHomeXrayShape(cfg config.Config, serviceID string) bool {
	if _, err := nfqwsPacketIntent(cfg); err != nil {
		return false
	}
	svc, known := a.autonomyService(serviceID)
	if !known || len(svc.CIDRs) != 1 || len(svc.SourceRefs) != 0 || len(svc.Domains) != 0 || !cfg.Services[serviceID].Enabled {
		return false
	}
	prefix, err := netip.ParsePrefix(svc.CIDRs[0])
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || !publicfetch.PublicPrefix(prefix) || !xrayHomeProbeMatches(svc.ProbeURL, prefix.Addr()) {
		return false
	}
	for _, probe := range svc.Probes {
		if probe.Required && !xrayHomeProbeMatches(probe.URL, prefix.Addr()) {
			return false
		}
	}
	set, err := config.EffectiveConfigResourceExclusions(cfg)
	if err != nil || len(set.BroadTLDs) != 0 {
		return false
	}
	for _, list := range [][]config.ResourceMatch{set.Manual, set.Russian} {
		for _, m := range list {
			if m.Kind != "ip" && m.Kind != "cidr" {
				return false
			}
		}
	}
	for _, rule := range set.LegacyRules {
		if (rule.Kind != "ip" && rule.Kind != "cidr") || rule.Action != "direct" || len(rule.DeviceIDs) != 0 {
			return false
		}
	}
	for id, state := range cfg.Services {
		if id != serviceID && state.Enabled {
			return false
		}
	}
	return true
}

// A locally supplied definition can override a stock ID. Only the stock
// web target and its complete TLS/content contract qualify for this check.
func (a *App) autonomyHomeWebCheck(cfg config.Config, p autonomy.Policy, s autonomy.Service) bool {
	if (s.ID != "telegram-web" && s.ID != "discord-web") || !s.Enabled || s.Removing || !s.AllLAN || len(s.Sources) != 0 || s.ExpectedRoute != "auto" ||
		!cfg.Services[s.ID].Enabled || cfg.AppliedServices[s.ID].Enabled || !slices.Contains(p.PreferredRoutes, "xray") || len(p.SourceIDs) == 0 {
		return false
	}
	if _, err := nfqwsPacketIntent(cfg); err != nil {
		return false
	}
	for _, rule := range cfg.NetworkPolicy.Rules {
		if len(rule.DeviceIDs) != 0 {
			return false
		}
	}
	service, ok := a.autonomyService(s.ID)
	if !ok || s.Definition != autonomyDefinition(service) || len(service.CIDRs) != 0 || len(service.SourceRefs) != 0 {
		return false
	}
	for _, stock := range catalog.WithWebDefaults(catalog.Catalog{}).Services {
		if stock.ID == s.ID {
			return service.ProbeURL == stock.ProbeURL && slices.Equal(service.Domains, stock.Domains) &&
				slices.Equal(service.Strategy, stock.Strategy) && reflect.DeepEqual(service.Probes, stock.Probes)
		}
	}
	return false
}

func (a *App) autonomyHomeXrayContext(ctx context.Context, cfg config.Config, s autonomy.Service, webCheckOnly bool) (context.Context, func() error, error) {
	if ctx == nil || ctx.Value(autonomyDeviceScopeKey{}) != nil || ctx.Value(autonomyHomeScopeKey{}) != nil || !s.AllLAN || len(s.Sources) != 0 ||
		(webCheckOnly && !a.autonomyHomeWebCheck(cfg, a.autonomyPolicy(), s)) || (!webCheckOnly && !a.autonomyHomeXrayShape(cfg, s.ID)) {
		return nil, nil, ErrListScopeChanged
	}
	a.managedListPolicyMu.Lock()
	p := a.managedListPolicy
	a.managedListPolicyMu.Unlock()
	if p == nil || !p.original() || p.closed.Load() || !p.startupReady || p.startupFailure != nil {
		return nil, nil, ErrListScopeChanged
	}
	b, err := newReviewedStockXrayHomeScopeBinding(ctx, a, p.provider)
	if err != nil {
		return nil, nil, err
	}
	h := &autonomyXrayHomeRound{app: a, store: a.Store, original: ctx, spec: s, policy: config.CloneNetworkPolicy(cfg.NetworkPolicy), consent: config.CloneDefaultRouteConsent(cfg.DefaultRouteConsent), binding: b, provider: p.provider}
	h.self = h
	h.webCheckOnly = webCheckOnly
	h.spec.Sources = slices.Clone(s.Sources)
	return context.WithValue(ctx, autonomyHomeScopeKey{}, h), h.close, nil
}

func (h *autonomyXrayHomeRound) close() error {
	h.mu.Lock()
	h.closed = true
	b, borrowed := h.binding, h.borrowed
	h.mu.Unlock()
	if !borrowed {
		return b.Close()
	}
	return nil
}

func (a *App) withAutonomyHomeWebCheck(ctx context.Context, cfg config.Config, s autonomy.Service, action func(context.Context)) (err error) {
	window, cancel := context.WithTimeout(ctx, defaultDataplaneApplyTimeout)
	defer cancel()
	owned, closeScope, err := a.autonomyHomeXrayContext(window, cfg, s, true)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeScope(); closeErr != nil {
			a.Operations.FenceJournal()
			err = closeErr
		}
	}()
	action(owned)
	return nil
}

func (h *autonomyXrayHomeRound) current(ctx context.Context, a *App, cfg config.Config, s autonomy.Service) bool {
	if h == nil || h.self != h || a == nil || h.store == nil || ctx == nil || ctx.Err() != nil || h.app != a || h.store != a.Store || ctx.Value(autonomyHomeScopeKey{}) != h || h.original == nil || h.original.Err() != nil || !reflect.DeepEqual(h.spec, s) || !reflect.DeepEqual(cfg.NetworkPolicy, h.policy) || !reflect.DeepEqual(cfg.DefaultRouteConsent, h.consent) {
		return false
	}
	d, bounded := ctx.Deadline()
	original, ok := h.original.Deadline()
	if !bounded || !ok || d.After(original) {
		return false
	}
	return h.currentBinding() != nil
}

func (h *autonomyXrayHomeRound) currentBinding() *xrayHomeScopeBinding {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	return h.binding
}

func (a *App) borrowAutonomyXrayHomeScope(ctx context.Context) (*xrayHomeScopeBinding, error) {
	if ctx == nil {
		return nil, ErrListScopeChanged
	}
	h, _ := ctx.Value(autonomyHomeScopeKey{}).(*autonomyXrayHomeRound)
	if h == nil || h.webCheckOnly || h.app != a || h.store != a.Store || !h.current(ctx, a, a.Store.Get(), h.spec) {
		return nil, ErrListScopeChanged
	}
	b := h.currentBinding()
	if b == nil {
		return nil, ErrListScopeChanged
	}
	if err := b.use(ctx, func(c context.Context) error { return c.Err() }); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.binding != b || h.borrowed || h.original.Err() != nil || ctx.Err() != nil {
		return nil, ErrListScopeChanged
	}
	h.borrowed = true
	return h.binding, nil
}

func (a *App) autonomyUsesHomeXray(cfg config.Config, p autonomy.Policy, s autonomy.Service) bool {
	return cfg.NetworkPolicy != nil && cfg.NetworkPolicy.Clients.Mode == "lan_except" && s.AllLAN && len(s.Sources) == 0 && (strings.HasPrefix(s.ExpectedRoute, "xray:node-") || s.ExpectedRoute == "auto" && a.autonomySearchEngine(cfg, p, s) == "xray") && a.autonomyHomeXrayShape(cfg, s.ID)
}

// A loan lasts until the execution joins and closes its actual owner. Recheck
// the published rollback before acquiring a NEW Home observer for the next
// candidate. The search separately validates its exact service/path failure.
func (h *autonomyXrayHomeRound) afterRollback(ctx context.Context, before config.Config, err error) bool {
	failure, ok := err.(*autonomyApplyFailure)
	if !ok || failure == nil || !failure.Execution.RollbackVerified || failure.Execution.State != "rolled-back" ||
		failure.Plan.Digest == "" || failure.Plan.Digest != failure.Execution.Digest || failure.Plan.PlanID != failure.Execution.PlanID ||
		!h.current(ctx, h.app, before, h.spec) || !reflect.DeepEqual(h.store.Get(), before) {
		return false
	}
	h.mu.Lock()
	old, borrowed := h.binding, h.borrowed
	h.mu.Unlock()
	if !borrowed || !old.original() {
		return false
	}
	old.base.mu.Lock()
	joined := old.base.closed && old.base.closeErr == nil
	old.base.mu.Unlock()
	if !joined || h.app.Dataplane.CheckExecutionRecovery(ctx) != nil {
		return false
	}
	status, readErr := h.app.Dataplane.Status()
	if readErr != nil || status.Execution == nil || !reflect.DeepEqual(*status.Execution, failure.Execution) {
		return false
	}
	b, openErr := newReviewedStockXrayHomeScopeBinding(ctx, h.app, h.provider)
	if openErr != nil {
		return false
	}
	h.mu.Lock()
	if h.closed || h.binding != old || !h.borrowed || h.original.Err() != nil || ctx.Err() != nil {
		h.mu.Unlock()
		if b.Close() != nil {
			h.app.Operations.FenceJournal()
		}
		return false
	}
	h.binding, h.borrowed = b, false
	h.mu.Unlock()
	return true
}

// Historical display of one isolated service result is allowed only while its
// exact permit, engine, WAN, reserve schedule and latest stored proof still agree.
func (a *App) autonomyHomeReserveUntil(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, eligible []string, nodes []nodestore.Node, profile string, now time.Time) time.Time {
	id := r.Reserves[0]
	if !slices.Contains(eligible, id) {
		return time.Time{}
	}
	for _, node := range nodes {
		if node.ID != id {
			continue
		}
		sourceUntil := allowedAutonomyNodeUntil(p, node, now)
		for _, record := range node.Health.History {
			if record.RoutePathID != "xray:"+id || record.ServiceID != s.ID || record.NetworkProfile != profile ||
				!record.CheckedAt.Equal(r.ReserveCheckedAt) || record.TestLevel != "service" || record.Verdict != "PASS" {
				continue
			}
			until := minTime(record.ExpiresAt, record.CheckedAt.Add(time.Duration(p.ReserveSeconds)*time.Second))
			until = minTime(until, sourceUntil)
			if until.After(now) {
				if _, err := a.Nodes.ResolveRouteForEngine(ctx, "xray", id, s.ID, profile, "", time.Time{}, now); err == nil {
					return until
				}
			}
		}
	}
	return time.Time{}
}
