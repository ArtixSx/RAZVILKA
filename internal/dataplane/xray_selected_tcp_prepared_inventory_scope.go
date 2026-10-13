package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// A single collector read of the SAME issued resource before any version,
// native Start or selector attempt. This neither extends the cold read nor
// supplies an active consumer, process, effect or cleanup capability.
type xraySelectedTCPPreparedInventoryScope struct {
	self      *xraySelectedTCPPreparedInventoryScope
	origin    *xraySelectedTCPPreparedInventoryOrigin
	checks    *NetworkPolicyChecks
	execution *xraySelectedTCPExecution
	resource  *XraySelectedTCPExecutionResource
	owner     *xrayOperationOwner
	identity  *networkPolicyIdentity
	provider  *netidentity.Provider
	inventory *BackendInventory
	original  context.Context
	bound     context.Context
	cleanup   bool
	record    ExecutionResource
	open      atomic.Bool
	closing   atomic.Bool
	captured  bool
	stock     *networkPolicyXraySelectedTCPStockObservation
	proxy     []networkPolicyProxyObservation
	nfq       []networkPolicyNFQObservation
	xray      []networkPolicyXraySelectedTCPObservation
}

type xraySelectedTCPPreparedInventoryScopeKey struct{}

// A flat copy cannot rebase its self/bound fields onto another context. This
// private original association has no constructor or renewal API outside the
// collector opener; copies retain its reference to the actual original read.
type xraySelectedTCPPreparedInventoryOrigin struct {
	read  *xraySelectedTCPPreparedInventoryScope
	bound context.Context
}

func (c *NetworkPolicyChecks) openXraySelectedTCPPreparedInventoryScope(ctx context.Context) (context.Context, *xraySelectedTCPPreparedInventoryScope, error) {
	if ctx == nil || ctx.Value(xraySelectedTCPPreparedInventoryScopeKey{}) != nil {
		return ctx, nil, ErrNetworkPolicyConsumers
	}
	if ctx.Value(xraySelectedTCPInventoryScopeKey{}) != nil || xraySelectedTCPFinite(ctx) != nil || ctx.Value(xraySelectedTCPReplacementKey{}) != nil {
		return ctx, nil, nil
	}
	value := ctx.Value(xraySelectedTCPExecutionKey{})
	if value == nil {
		return ctx, nil, nil
	}
	e, ok := value.(*xraySelectedTCPExecution)
	if !ok || e == nil || e.self != e || c == nil || e.checks != c {
		return ctx, nil, ErrXrayOperationOwner
	}
	e.mu.Lock()
	r := e.resource
	e.mu.Unlock()
	if r == nil {
		return ctx, nil, nil
	}
	if c.identity == nil || c.inventory == nil || c.current(ctx) != nil {
		return ctx, nil, ErrNetworkPolicyConsumers
	}
	if r.self != r || r.scope == nil || r.scope.execution == nil || r.owner == nil || r.owner.self != r.owner || r.material != e.material || r.owner.material != r.material || r.material == nil || r.material.execution != e {
		return ctx, nil, ErrXrayOperationOwner
	}
	r.scope.mu.Lock()
	index, err := r.matching()
	var record ExecutionResource
	if err == nil {
		record = cloneExecutionResources([]ExecutionResource{r.scope.execution.Resources[index]})[0]
	}
	r.scope.mu.Unlock()
	if err != nil {
		return ctx, nil, err
	}
	if record.State != "prepared" || record.Phase != "planned" {
		return ctx, nil, nil // Other lifecycles retain their existing exact reads.
	}
	s := &xraySelectedTCPPreparedInventoryScope{checks: c, execution: e, resource: r, owner: r.owner, identity: c.identity,
		provider: c.identity.provider, inventory: c.inventory, original: ctx, cleanup: r.material.IsCleanupContext(ctx), record: record}
	s.self = s
	s.bound = context.WithValue(ctx, xraySelectedTCPPreparedInventoryScopeKey{}, s)
	s.origin = &xraySelectedTCPPreparedInventoryOrigin{read: s, bound: s.bound}
	s.open.Store(true)
	if err = s.currentFinal(s.bound); err == nil {
		// No metadata/resource/observation mutex or Provider boundary is held.
		err = s.owner.checkHeld(ctx, s.cleanup)
	}
	if err == nil {
		err = s.currentFinal(s.bound)
	}
	if err != nil {
		s.close()
		return ctx, nil, err
	}
	return s.bound, s, nil
}

// Pure metadata/anchored-file checks. Native intent changes the original
// record to process-pending under scope.mu BEFORE any version/Start syscall.
// This method takes no observation lock: actual consumer observers call it
// while already holding that lock; currentFinal supplies the final bookend.
func (s *xraySelectedTCPPreparedInventoryScope) current(ctx context.Context) error {
	if s == nil || s.self != s || s.origin == nil || s.origin.read != s || s.origin.bound != s.bound || !s.open.Load() || s.checks == nil || s.execution == nil || s.execution.self != s.execution ||
		s.resource == nil || s.resource.self != s.resource || s.owner == nil || s.owner.self != s.owner || s.original == nil || s.bound == nil || ctx == nil ||
		s.bound.Value(xraySelectedTCPPreparedInventoryScopeKey{}) != s || ctx.Value(xraySelectedTCPPreparedInventoryScopeKey{}) != s ||
		ctx.Value(xraySelectedTCPExecutionKey{}) != s.execution || ctx.Value(xrayOperationOwnerKey{}) != s.owner ||
		ctx.Value(xrayOperationMaterialKey{}) != s.owner.material || xraySelectedTCPFinite(ctx) != nil || ctx.Value(xraySelectedTCPReplacementKey{}) != nil ||
		s.owner.material == nil || s.owner.material.closed.Load() || s.owner.material.IsCleanupContext(ctx) != s.cleanup || s.owner.material.IsCleanupContext(s.original) != s.cleanup {
		return ErrXrayOperationOwner
	}
	deadline, finite := ctx.Deadline()
	originalDeadline, originalFinite := s.original.Deadline()
	if !finite || !originalFinite || deadline.After(originalDeadline) || ctx.Err() != nil || s.original.Err() != nil {
		return errors.Join(ErrXrayOperationOwner, ctx.Err(), s.original.Err())
	}
	c, e, r, o := s.checks, s.execution, s.resource, s.owner
	if s.identity == nil || s.provider == nil || s.inventory == nil || c.identity != s.identity || c.inventory != s.inventory ||
		s.identity.provider != s.provider || s.inventory.reader.Provider != s.provider || r.scope == nil || o.scope != r.scope || o.material != r.material ||
		r.material == nil || r.material.execution != e || r.material.adapter != c.adapters["xray"] || c.gate == nil || c.gate.identity != s.identity || c.current(ctx) != nil {
		return ErrXrayOperationOwner
	}
	e.mu.Lock()
	current := e.resource == r && e.material == o.material && e.checks == c && e.bound && !e.started && !e.retired && !e.preparing && e.replacement == nil &&
		reflect.DeepEqual(e.plan, r.scope.plan)
	e.mu.Unlock()
	if !current {
		return ErrXrayOperationOwner
	}
	if !s.cleanup {
		o.mu.Lock()
		revoked := o.revoked
		o.mu.Unlock()
		if revoked != nil {
			return revoked
		}
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	index, err := r.matching()
	if err != nil || r.scope.retained || r.scope.pending || r.scope.manager != c.manager || r.scope.managerRoot != c.root || r.scope.networkIdentity != s.identity ||
		r.scope.adapterOwner != c.adapters["xray"] || !r.scope.observationOpen.Load() || len(r.scope.xraySelectedTCP) != 1 || r.scope.resourceCount() != 1 ||
		r.scope.checkOriginalOwner(ctx, nil, !s.cleanup, s.cleanup) != nil || !reflect.DeepEqual(s.record, r.scope.execution.Resources[index]) {
		return ErrXrayOperationOwner
	}
	return nil
}

// Called ONLY with this resource's observationMu read lock already held.
func (s *xraySelectedTCPPreparedInventoryScope) observationHeld(ctx context.Context) error {
	if err := s.current(ctx); err != nil {
		return err
	}
	r := s.resource
	if r.versionUsed || r.versionVerified || r.versionChild != nil || r.startUsed || r.startACK || r.startFailed || r.child != nil || r.birth != nil ||
		r.selectorUsed || r.active || r.stopped || r.descriptorsClosed || r.config == nil || r.executable == nil {
		return ErrXrayOperationOwner
	}
	return nil
}

func (s *xraySelectedTCPPreparedInventoryScope) currentFinal(ctx context.Context) error {
	if err := s.current(ctx); err != nil {
		return err
	}
	r := s.resource
	r.observationMu.RLock()
	err := s.observationHeld(ctx)
	r.observationMu.RUnlock()
	return err
}

// Retain comparison facts only. Their original descriptors are closed by the
// provisional capture; confirm obtains fresh actual observations with new FDs.
func (s *xraySelectedTCPPreparedInventoryScope) remember(stock *networkPolicyXraySelectedTCPStockObservation, proxy []networkPolicyProxyObservation, nfq []networkPolicyNFQObservation, xray []networkPolicyXraySelectedTCPObservation) error {
	if s.captured || stock == nil || stock.resource != s.resource || stock.pre != nil || stock.pair != nil || len(xray) != 1 ||
		xray[0].resource != s.resource || !xray[0].beforeStart || !xray[0].absent || xray[0].borrowed {
		return ErrNetworkPolicyConsumers
	}
	s.stock, s.proxy, s.nfq, s.xray = stock, slices.Clone(proxy), slices.Clone(nfq), slices.Clone(xray)
	s.captured = true
	return nil
}

func (s *xraySelectedTCPPreparedInventoryScope) checkClosing(ctx context.Context) error {
	err := s.currentFinal(ctx)
	if err == nil && (!s.captured || !s.closing.CompareAndSwap(false, true)) {
		err = ErrXrayOperationOwner
	}
	if err == nil {
		err = s.owner.checkHeld(s.original, s.cleanup)
	}
	if err == nil {
		err = s.currentFinal(ctx)
	}
	if err != nil {
		s.close()
	}
	return err
}

func (s *xraySelectedTCPPreparedInventoryScope) confirm(ctx context.Context, previous BackendInventorySnapshot, lan *LANPolicyRuntimePlan, wg []networkPolicyWGObservation) error {
	if err := s.currentFinal(ctx); err != nil {
		return err
	}
	if !s.captured || !s.closing.Load() {
		return ErrXrayOperationOwner
	}
	c := s.checks
	proxy, err := c.proxyConsumers(ctx, lan)
	defer closeNetworkPolicyProxyObservations(proxy)
	if err != nil || !equalNetworkPolicyProxyObservations(s.proxy, proxy) {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	nfq, err := c.nfqConsumers(ctx, lan)
	defer func() {
		for _, o := range nfq {
			o.close()
		}
	}()
	if err != nil || !equalNetworkPolicyNFQObservations(s.nfq, nfq) {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	xray, err := c.xraySelectedTCPConsumers(ctx, lan)
	defer closeNetworkPolicyXrayObservations(xray)
	if err != nil || !equalNetworkPolicyXraySelectedTCPObservations(s.xray, xray) {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	queue, err := c.stockQueueExecution(ctx)
	if err != nil || queue != nil {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	stock, err := c.xraySelectedTCPStockExecution(ctx)
	if err != nil || !s.stock.equal(stock) {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	last, err := c.read(ctx, c.network)
	if err != nil || !reflect.DeepEqual(previous, last) {
		return errors.Join(ErrBackendInventoryUnknown, err)
	}
	// No source/control/physical/process or Provider callback after this image.
	rows, err := stock.comparison(last)
	for _, o := range wg {
		err = errors.Join(err, o.currentFiles(ctx))
	}
	for _, o := range nfq {
		err = errors.Join(err, o.current(ctx))
	}
	for _, o := range xray {
		err = errors.Join(err, o.current(ctx))
	}
	return errors.Join(err, s.currentFinal(ctx), s.consumerFiles(proxy, nfq), stock.current(ctx), checkNetworkPolicyProxyObservations(proxy),
		checkNetworkPolicyInventoryWithWG(last, *c.identity, lan, c.identity.inventoryMode(lan), proxy, rows, nfq, xray, wg))
}

func (s *xraySelectedTCPPreparedInventoryScope) consumerFiles(proxy []networkPolicyProxyObservation, nfq []networkPolicyNFQObservation) error {
	for id, view := range s.checks.proxies {
		present := slices.ContainsFunc(proxy, func(o networkPolicyProxyObservation) bool { return o.engine == id })
		if !present {
			if _, err := os.Lstat(view.forwardingPath()); !errors.Is(err, os.ErrNotExist) {
				return errors.Join(ErrNetworkPolicyConsumers, err)
			}
		}
	}
	if len(nfq) == 0 {
		if a, ok := s.checks.adapters["nfqws2"].(*NFQWS2Adapter); ok && a != nil {
			nfqws2ActiveAdapterMu.Lock()
			absent := a.activeExecution == nil && a.activeProcess == nil
			nfqws2ActiveAdapterMu.Unlock()
			if !absent {
				return ErrNetworkPolicyConsumers
			}
		}
	}
	return nil
}

func (s *xraySelectedTCPPreparedInventoryScope) close() {
	if s != nil {
		s.open.Store(false)
	}
}
