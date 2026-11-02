package dataplane

import (
	"context"
	"path/filepath"
)

// A private settlement cursor belongs to the SAME actual transit issuer.
// A serialized removed/unused row cannot supply the one-shot readback ACK.
func (s *executionResourceScope) settleMihomoCheckingTransit(ctx context.Context, resource *executionTransitResource, spec NodeTransitSpec, root, digest string, mode networkPolicyTransitReadbackMode) error {
	match := func() (int, error) {
		if resource == nil || mode != networkPolicyTransitRemoved && mode != networkPolicyTransitUnused || s.issued[filepath.Base(resource.relative)] != resource || resource.spec != spec || resource.root != root || resource.digest != digest || resource.readback == nil {
			return -1, ErrNodeTransitUnavailable
		}
		if err := s.check(ctx, resource, false); err != nil {
			return -1, err
		}
		for i, row := range s.execution.Resources {
			if row.ID != filepath.Base(resource.relative) {
				continue
			}
			if row.Kind != "node-transit" || row.NodeTransit == nil || *row.NodeTransit != spec || row.Generation != digest || row.EffectsDigest != resource.effects {
				return -1, ErrNodeTransitUnavailable
			}
			if row.State != "prepared" && (row.State != string(mode) || resource.settlementReadback != mode) {
				return -1, ErrNodeTransitUnavailable
			}
			if resource.settlementReadback != "" && resource.settlementReadback != mode {
				return -1, ErrNodeTransitUnavailable
			}
			return i, nil
		}
		return -1, ErrNodeTransitUnavailable
	}
	s.mu.Lock()
	_, err := match()
	prior := resource != nil && resource.settlementReadback == mode
	s.mu.Unlock()
	if err != nil {
		return err
	}
	readMode := mode
	if mode == networkPolicyTransitUnused && prior {
		readMode = networkPolicyTransitUnusedCurrent
	}
	if err := resource.readback(ctx, spec, root, digest, readMode); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Preserve the actual one-shot ACK even if the final guard or publication
	// now fails. It permits fresh read-only comparison, never effects/reuse.
	if s.issued[filepath.Base(resource.relative)] != resource {
		return ErrNodeTransitUnavailable
	}
	resource.settlementReadback = mode
	index, err := match()
	if err != nil {
		return err
	}
	s.execution.Resources[index].State = string(mode)
	c := s.mihomoLive.healthCheck
	if c == nil || c.self != c || c.owner != s.mihomoLive {
		return ErrExecutionJournal
	}
	c.settling = resource
	defer func() { c.settling = nil }()
	err = s.persist()
	if err == nil && mode == networkPolicyTransitUnused {
		resource.unusedSettled = true
	}
	return err
}
