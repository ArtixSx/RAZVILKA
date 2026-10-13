package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// One original collector call owns this cold read. It is never an issuer,
// resource, process, receipt or cleanup authority. Full original checks bracket
// the first capture outside Provider.WithCurrent; the final image is followed
// only by the same original metadata/file checks. No result survives close.
type xraySelectedTCPInventoryScope struct {
	self      *xraySelectedTCPInventoryScope
	checks    *NetworkPolicyChecks
	pre       *xraySelectedTCPPreResource
	identity  *networkPolicyIdentity
	provider  *netidentity.Provider
	inventory *BackendInventory
	original  context.Context
	bound     context.Context
	cleanup   bool
	open      atomic.Bool
	closing   atomic.Bool
}

type xraySelectedTCPInventoryScopeKey struct{}

func (c *NetworkPolicyChecks) openXraySelectedTCPInventoryScope(ctx context.Context) (context.Context, *xraySelectedTCPInventoryScope, error) {
	if ctx == nil || ctx.Value(xraySelectedTCPInventoryScopeKey{}) != nil {
		return ctx, nil, ErrNetworkPolicyConsumers
	}
	// Existing finite and replacement scopes keep their own strict owners.
	if xraySelectedTCPFinite(ctx) != nil || ctx.Value(xraySelectedTCPReplacementKey{}) != nil {
		return ctx, nil, nil
	}
	value := ctx.Value(xraySelectedTCPPreResourceKey{})
	if value == nil {
		return ctx, nil, nil
	}
	p, ok := value.(*xraySelectedTCPPreResource)
	if !ok || p == nil || p.self != p || p.execution == nil || p.execution.self != p.execution || p.execution.checks != c || p.owner == nil || p.owner.self != p.owner {
		return ctx, nil, ErrXrayOperationOwner
	}
	p.execution.mu.Lock()
	resource := p.execution.resource
	p.execution.mu.Unlock()
	if resource != nil {
		return ctx, nil, nil // Actual resource/process observations stay unchanged.
	}
	if err := p.current(ctx); err != nil {
		return ctx, nil, err
	}
	cleanup := p.owner.material.IsCleanupContext(ctx)
	if err := p.owner.checkHeld(ctx, cleanup); err != nil {
		return ctx, nil, err
	}
	if err := p.current(ctx); err != nil {
		return ctx, nil, err
	}
	s := &xraySelectedTCPInventoryScope{checks: c, pre: p, identity: c.identity, provider: c.identity.provider, inventory: c.inventory, original: ctx, cleanup: cleanup}
	s.self = s
	s.open.Store(true)
	bound := context.WithValue(ctx, xraySelectedTCPInventoryScopeKey{}, s)
	s.bound = bound
	if err := s.current(bound); err != nil {
		s.close()
		return ctx, nil, err
	}
	return bound, s, nil
}

// Pure checks only: this deliberately does not call source/control/physical or
// Provider callbacks inside the bounded complete inventory capture.
func (s *xraySelectedTCPInventoryScope) current(ctx context.Context) error {
	if s == nil || s.self != s || !s.open.Load() || s.checks == nil || s.pre == nil || s.pre.self != s.pre || s.original == nil || s.bound == nil || ctx == nil ||
		s.bound.Value(xraySelectedTCPInventoryScopeKey{}) != s ||
		ctx.Value(xraySelectedTCPInventoryScopeKey{}) != s || s.pre.execution == nil || s.pre.execution.checks != s.checks || s.pre.owner == nil || s.pre.owner.material == nil ||
		s.pre.owner.material.IsCleanupContext(ctx) != s.cleanup || s.pre.owner.material.IsCleanupContext(s.original) != s.cleanup {
		return ErrXrayOperationOwner
	}
	if s.identity == nil || s.provider == nil || s.inventory == nil || s.checks.identity != s.identity || s.checks.inventory != s.inventory ||
		s.identity.provider != s.provider || s.inventory.reader.Provider != s.provider {
		return ErrXrayOperationOwner
	}
	originalDeadline, originalFinite := s.original.Deadline()
	deadline, finite := ctx.Deadline()
	if !originalFinite || !finite || deadline.After(originalDeadline) || s.original.Err() != nil || ctx.Err() != nil {
		return errors.Join(ErrXrayOperationOwner, s.original.Err(), ctx.Err())
	}
	if err := s.checks.current(ctx); err != nil {
		return err
	}
	if !s.cleanup {
		s.pre.owner.mu.Lock()
		revoked := s.pre.owner.revoked
		s.pre.owner.mu.Unlock()
		if revoked != nil {
			return revoked
		}
	}
	return s.pre.current(ctx)
}

func (s *xraySelectedTCPInventoryScope) checkClosing(ctx context.Context) error {
	if err := s.current(ctx); err != nil {
		s.close()
		return err
	}
	if !s.closing.CompareAndSwap(false, true) {
		s.close()
		return ErrXrayOperationOwner
	}
	if err := s.pre.owner.checkHeld(s.original, s.cleanup); err != nil {
		s.close()
		return err
	}
	err := s.current(ctx)
	if err != nil {
		s.close()
	}
	return err
}

// Re-observe every other producer after the outside closing guard. Cold stock
// is deliberately zero-consumer: a process/receipt publication can change
// ownership before it creates any kernel row, so image equality alone cannot
// prove this absence. Active/finite/replacement allowances use their old path.
func (s *xraySelectedTCPInventoryScope) confirm(ctx context.Context, previous BackendInventorySnapshot, lan *LANPolicyRuntimePlan) error {
	if err := s.current(ctx); err != nil {
		return err
	}
	if !s.closing.Load() {
		return ErrXrayOperationOwner
	}
	c := s.checks
	proxy, err := c.proxyConsumers(ctx, lan)
	defer closeNetworkPolicyProxyObservations(proxy)
	if err != nil || len(proxy) != 0 {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	nfq, err := c.nfqConsumers(ctx, lan)
	defer func() {
		for _, o := range nfq {
			o.close()
		}
	}()
	if err != nil || len(nfq) != 0 {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	xray, err := c.xraySelectedTCPConsumers(ctx, lan)
	defer closeNetworkPolicyXrayObservations(xray)
	if err != nil || len(xray) != 0 {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	queue, err := c.stockQueueExecution(ctx)
	if err != nil || queue != nil {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	stock, err := c.xraySelectedTCPStockExecution(ctx)
	if err != nil || stock == nil || stock.pre != s.pre || stock.resource != nil || stock.pair != nil {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	last, err := c.read(ctx, c.network)
	if err != nil || !reflect.DeepEqual(previous, last) {
		return errors.Join(ErrBackendInventoryUnknown, err)
	}
	// Only original in-memory identity and anchored-file comparisons follow
	// the true final image. No source/physical/process/Provider callback here.
	rows, err := stock.comparison(last)
	return errors.Join(err, s.current(ctx), s.consumerAbsence(), stock.current(ctx),
		checkNetworkPolicyInventoryWithWG(last, *c.identity, lan, c.identity.inventoryMode(lan), nil, rows, nil, nil, nil))
}

func (s *xraySelectedTCPInventoryScope) consumerAbsence() error {
	c := s.checks
	for _, view := range c.proxies {
		if _, err := os.Lstat(view.forwardingPath()); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	if a, ok := c.adapters["nfqws2"].(*NFQWS2Adapter); ok && a != nil {
		nfqws2ActiveAdapterMu.Lock()
		absent := a.activeExecution == nil && a.activeProcess == nil
		nfqws2ActiveAdapterMu.Unlock()
		if !absent {
			return ErrNetworkPolicyConsumers
		}
	}
	return nil
}

func (s *xraySelectedTCPInventoryScope) close() {
	if s != nil {
		s.open.Store(false)
	}
}
