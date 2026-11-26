package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// A private, single-read comparison bracket, never ownership of another queue.
// Only constructors that read the original concrete source can issue it. The
// precompiled caller must retain its original direct execution provenance.
type nfqwsScopedStockQueueProof struct {
	inventory *BackendInventory
	provider  *netidentity.Provider
	expected  netidentity.Identity
	queue     uint16
	opening   BackendInventorySnapshot
	stockRows []BackendInventoryRow
	binding   *NFQWSScopedBinding
	plan      *NFQWSScopedPlan
	used      atomic.Bool
}

func nfqwsScopedPrecompiledStockQueueProof(ctx context.Context, inventory *BackendInventory, expected netidentity.Identity, managedQueue uint16) (*nfqwsScopedStockQueueProof, error) {
	if ctx == nil || inventory == nil || expected.Validate() != nil || managedQueue == 0 {
		return nil, ErrNFQWSScopedOwner
	}
	p := &nfqwsScopedStockQueueProof{inventory: inventory, provider: inventory.reader.Provider, expected: expected, queue: managedQueue}
	snapshot, rows, err := p.read(ctx)
	if err != nil {
		return nil, err
	}
	p.opening, p.stockRows = snapshot, rows
	return p, nil
}

func (b *NFQWSScopedBinding) stockQueueProof(ctx context.Context, plan *NFQWSScopedPlan) (*nfqwsScopedStockQueueProof, error) {
	identity, err := nfqwsScopedTypedNetwork(plan)
	if ctx == nil || b == nil || b.network == nil || err != nil || plan.lan == nil || plan.lan.Mode != LANPolicyNFQWSDirectMode || plan.resources.Queue != plan.spec.Queue || plan.resources.Queue == 0 {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	p := &nfqwsScopedStockQueueProof{inventory: &b.network.inventory, provider: b.network.provider, expected: identity, queue: plan.resources.Queue, binding: b, plan: plan}
	snapshot, rows, err := p.read(ctx)
	if err != nil {
		return nil, err
	}
	p.opening, p.stockRows = snapshot, rows
	return p, nil
}

func (p *nfqwsScopedStockQueueProof) read(ctx context.Context) (BackendInventorySnapshot, []BackendInventoryRow, error) {
	refuse := func(err error) (BackendInventorySnapshot, []BackendInventoryRow, error) {
		return BackendInventorySnapshot{}, nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if p == nil || ctx == nil || p.inventory == nil || p.expected.Validate() != nil || p.queue == 0 || p.provider == nil || p.inventory.reader.Provider != p.provider ||
		p.inventory.reader.Runner == nil || p.inventory.reader.CheckTools == nil || !lanPolicyHash(p.inventory.review) {
		return refuse(nil)
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	var snapshot BackendInventorySnapshot
	var rows []BackendInventoryRow
	var err error
	if p.binding != nil || p.plan != nil {
		b, plan := p.binding, p.plan
		identity, e := nfqwsScopedTypedNetwork(plan)
		if b == nil || b.network == nil || plan == nil || e != nil || identity != p.expected || plan.resources.Queue != p.queue ||
			plan.lan == nil || plan.lan.Mode != LANPolicyNFQWSDirectMode || p.inventory != &b.network.inventory {
			return refuse(e)
		}
		image, e := b.network.rules(ctx, plan)
		if e != nil {
			return refuse(e)
		}
		rows, err = b.stockComparisonRows(plan, image)
		snapshot = image.capture.snapshot
	} else {
		snapshot, err = p.inventory.Read(ctx, p.expected)
		if err == nil {
			rows, err = inspectNFQWSDirectStockQueues(snapshot, p.queue)
		}
	}
	if err != nil || snapshot.RequireComplete() != nil || snapshot.Scope.Network != p.expected || snapshot.Scope.ToolReviewID != p.inventory.review ||
		snapshot.IPTables != p.inventory.reader.IPTables || snapshot.IP6Tables != p.inventory.reader.IP6Tables {
		return refuse(err)
	}
	return snapshot, rows, ctx.Err()
}

func (p *nfqwsScopedStockQueueProof) consume(ctx context.Context) error {
	if p == nil || ctx == nil || !p.used.CompareAndSwap(false, true) || ctx.Err() != nil || p.inventory == nil || p.opening.RequireComplete() != nil ||
		p.opening.Scope.Network != p.expected || p.queue == 0 || p.provider == nil || p.inventory.reader.Provider != p.provider ||
		p.opening.Scope.ToolReviewID != p.inventory.review || p.opening.IPTables != p.inventory.reader.IPTables || p.opening.IP6Tables != p.inventory.reader.IP6Tables {
		return ErrNFQWSScopedOwner
	}
	return nil
}

func (p *nfqwsScopedStockQueueProof) close(ctx context.Context) error {
	if p == nil || !p.used.Load() {
		return ErrNFQWSScopedOwner
	}
	snapshot, rows, err := p.read(ctx)
	if err != nil || !p.sameClosing(snapshot, rows) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return ctx.Err()
}

func (p *nfqwsScopedStockQueueProof) sameClosing(snapshot BackendInventorySnapshot, rows []BackendInventoryRow) bool {
	return p != nil && p.used.Load() && reflect.DeepEqual(p.opening, snapshot) && reflect.DeepEqual(p.stockRows, rows)
}

// Derive numbers only from the exact OUTPUT-disjoint comparison rows from the
// original whole capture. No preset, queue range or caller-supplied ID list.
func (p *nfqwsScopedStockQueueProof) contains(queue uint16) bool {
	if p == nil || !p.used.Load() || queue == p.queue {
		return false
	}
	return slices.ContainsFunc(p.stockRows, func(row BackendInventoryRow) bool {
		a, err := nfqwsDirectStockRuleAction(row.Tokens)
		return err == nil && a.target == "NFQUEUE" && a.queue != nil && *a.queue == queue
	})
}
