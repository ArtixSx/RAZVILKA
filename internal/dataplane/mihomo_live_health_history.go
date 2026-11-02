package dataplane

import "path/filepath"

// The private registration closure is called only after the original probe's
// synchronous body AND its native deferred removal/inspection have returned.
// A persisted removed row by itself can never manufacture this acknowledgment.
func (s *executionResourceScope) finishMihomoTransit(resource *executionTransitResource) error {
	if s == nil || resource == nil {
		return ErrNodeTransitUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.mihomoLive == nil || s.mihomoLive.scope != s || s.mihomoLive.self != s.mihomoLive || s.adapter != "mihomo" || resource.finished {
		return ErrNodeTransitUnavailable
	}
	id := filepath.Base(resource.relative)
	if s.issued[id] != resource {
		return ErrNodeTransitUnavailable
	}
	for _, row := range s.execution.Resources {
		if row.ID == id {
			if row.Kind != "node-transit" || row.NodeTransit == nil || *row.NodeTransit != resource.spec || row.Generation != resource.digest || row.EffectsDigest != resource.effects || (row.State != "removed" && row.State != "unused") || row.State == "removed" && !resource.admitted || row.State == "unused" && !resource.unusedSettled {
				return ErrNodeTransitUnavailable
			}
			resource.finished = true
			return nil
		}
	}
	return ErrNodeTransitUnavailable
}
