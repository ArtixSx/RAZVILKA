package dataplane

import (
	"context"
	"errors"
)

// A comparison bound to the original Apply participant. Queue numbers, chain
// names and decoded records cannot construct this owner or its context key.
type networkPolicyStockQueueObservation struct {
	execution *nfqws2ActiveExecution
	queue     uint16
	retired   bool
}

func (c *NetworkPolicyChecks) stockQueueExecution(ctx context.Context) (*networkPolicyStockQueueObservation, error) {
	if c == nil || ctx == nil {
		return nil, ErrNetworkPolicyConsumers
	}
	value := ctx.Value(nfqws2ActiveExecutionKey{})
	if value == nil {
		return nil, nil // The strict predicate will refuse every foreign queue.
	}
	e, ok := value.(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || c.gate == nil || c.gate.identity == nil || c.identity == nil ||
		c.gate.identity.mode != LANPolicyNFQWSDirectMode || e.plan.LAN == nil || e.plan.LAN.Mode != LANPolicyNFQWSDirectMode ||
		e.material.manager != c.manager || e.material.managerRoot != c.root || e.material.adapter != c.adapters["nfqws2"] ||
		e.gate != c.gate || e.lan != c.binding || e.runtime != c.runtime || e.identity != c.identity ||
		e.material.provider != c.identity.provider || e.material.registryGeneration != c.generation || c.inventory == nil ||
		e.inventory.reader.Provider != c.inventory.reader.Provider || e.inventory.review != c.inventory.review ||
		e.inventory.reader.IPTables != c.inventory.reader.IPTables || e.inventory.reader.IP6Tables != c.inventory.reader.IP6Tables ||
		!sameNetworkPolicyDependency(e.inventory.reader.Runner, c.inventory.reader.Runner) {
		return nil, ErrNetworkPolicyConsumers
	}
	e.mu.Lock()
	q, retired, spec := e.material.queue, e.retired, e.spec.Clone()
	e.mu.Unlock()
	e.material.mu.Lock()
	bound, closed := e.material.executionBound, e.material.closed
	e.material.mu.Unlock()
	if !bound || closed && !retired {
		return nil, ErrNetworkPolicyConsumers
	}
	if q == 0 || spec.Queue != q || len(spec.Matches) == 0 || spec.NetworkIdentity == nil || *spec.NetworkIdentity != c.network {
		return nil, ErrNetworkPolicyConsumers
	}
	if retired && e.resource != nil && e.resource.scope != nil && !e.resource.scope.observationOpen.Load() {
		if err := checkNFQWSRetiredInventoryContext(ctx, c, e); err != nil {
			return nil, err
		}
	}
	if err := e.owners(ctx); err != nil {
		return nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	return &networkPolicyStockQueueObservation{execution: e, queue: q, retired: retired}, nil
}

func (o *networkPolicyStockQueueObservation) equal(other *networkPolicyStockQueueObservation) bool {
	if o == nil || other == nil {
		return o == other
	}
	return o.execution == other.execution && o.queue == other.queue && o.retired == other.retired
}

// Pure bookend: no process/source/physical/tool callback after the last image.
func (o *networkPolicyStockQueueObservation) current(ctx context.Context) error {
	if o == nil {
		return nil
	}
	e := o.execution
	if ctx == nil || ctx.Err() != nil || e == nil || e.self != e || e.material == nil || e.material.self != e.material {
		return ErrNetworkPolicyConsumers
	}
	e.mu.Lock()
	unchanged := e.material.queue == o.queue && e.spec.Queue == o.queue && e.retired == o.retired
	started := e.started
	e.mu.Unlock()
	nfqws2ActiveAdapterMu.Lock()
	associated := e.material.adapter != nil && (e.material.adapter.activeExecution == e || (!started || o.retired) && e.material.adapter.activeExecution == nil && e.material.adapter.activeProcess == nil)
	nfqws2ActiveAdapterMu.Unlock()
	if !unchanged || !associated {
		return ErrNetworkPolicyConsumers
	}
	if o.retired && e.resource != nil && e.resource.scope != nil && !e.resource.scope.observationOpen.Load() {
		return nfqwsRetiredInventoryPureCurrent(ctx, e)
	}
	return nil
}

func (o *networkPolicyStockQueueObservation) comparison(s BackendInventorySnapshot, consumers []networkPolicyNFQObservation) ([]BackendInventoryRow, error) {
	if o == nil {
		return nil, nil
	}
	e := o.execution
	if s.Scope.Network != e.identity.value || s.Scope.ToolReviewID != e.inventory.review || s.IPTables != e.inventory.reader.IPTables || s.IP6Tables != e.inventory.reader.IP6Tables {
		return nil, ErrNetworkPolicyConsumers
	}
	return networkPolicyStockQueueRows(s, o.queue, e, consumers)
}

// Pure comparison only. Actual observation/receipt ownership is established by
// the caller; optional missing planned effects are never invented in the image.
func networkPolicyStockQueueRows(s BackendInventorySnapshot, queue uint16, e *nfqws2ActiveExecution, consumers []networkPolicyNFQObservation) ([]BackendInventoryRow, error) {
	foreign := false
	for _, row := range s.Rows {
		foreign = foreign || !networkPolicyNFQRow(row) && nfqwsDirectStockOtherTableQueue(row.Tokens)
	}
	if !foreign {
		return nil, nil
	}
	allowed := map[string]int{}
	for _, consumer := range consumers {
		if consumer.execution != e || len(consumer.rows) != len(consumer.required) {
			return nil, ErrNetworkPolicyConsumers
		}
		for _, row := range consumer.rows {
			key := networkPolicyRowKey(row, true)
			if key == "" || !networkPolicyNFQRow(row) {
				return nil, ErrNetworkPolicyConsumers
			}
			allowed[key]++
		}
	}
	var exactOwned []BackendInventoryRow
	for _, row := range s.Rows {
		if !networkPolicyNFQRow(row) {
			continue
		}
		key := networkPolicyRowKey(row, true)
		if allowed[key] > 0 {
			exactOwned = append(exactOwned, row)
			allowed[key]--
		}
	}
	return inspectNFQWSDirectStockQueuesWithOwned(s, queue, exactOwned)
}
