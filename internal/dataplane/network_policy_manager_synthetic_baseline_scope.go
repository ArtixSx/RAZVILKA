package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// These private hooks retain original producer pointers only. The definition
// in execution.json remains comparison metadata and cannot register a source.
func (s *executionResourceScope) registerSyntheticBaselineCoordinator(ctx context.Context, c *syntheticBaselineCoordinator) error {
	if s == nil || c == nil || c.self != c || c.binding == nil || c.binding.scope != s || c.local(ctx) != nil {
		return ErrSyntheticBaselineTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.syntheticClosing || s.failure != nil || s.syntheticBaselineSource != nil && s.syntheticBaselineSource != c {
		return ErrSyntheticBaselineTransition
	}
	if err := s.checkOriginalOwner(ctx, nil, true, false); err != nil {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	s.syntheticBaselineSource = c
	return nil
}

func (s *executionResourceScope) syntheticBaselineCommandTools(ctx context.Context, b *SyntheticDNSExecutionBinding) (*SyntheticDNSCommandTools, error) {
	if s == nil {
		return nil, ErrSyntheticBaselineTransition
	}
	s.mu.Lock()
	c := s.syntheticBaselineSource
	if !s.open || s.syntheticClosing || s.failure != nil || c == nil || c.self != c || c.binding != b || b == nil || b.scope != s {
		s.mu.Unlock()
		return nil, ErrSyntheticBaselineTransition
	}
	s.mu.Unlock()
	if err := c.Current(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syntheticBaselineSource != c || !s.open || s.syntheticClosing || s.failure != nil || c.local(ctx) != nil {
		return nil, ErrSyntheticBaselineTransition
	}
	return c.tools, nil
}

func (s *executionResourceScope) lookupSyntheticBaseline(ctx context.Context, b *SyntheticDNSExecutionBinding, mapping *dnscontrol.SyntheticDNSMapping, backend *BackendInventory, capture *DomainPolicyTCPCapture) (*syntheticBaselineExecutionResource, error) {
	if s == nil || b == nil || b.scope != s || mapping == nil || backend == nil || capture == nil {
		return nil, ErrSyntheticBaselineTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.syntheticBaselineSource
	if c == nil || c.binding != b || c.backend != backend || c.capture != capture || c.local(ctx) != nil || !s.open || s.syntheticClosing || s.failure != nil {
		return nil, ErrSyntheticBaselineTransition
	}
	for _, r := range s.syntheticBaselines {
		if r.mapping == mapping {
			if r.binding != b || r.backend != backend || r.capture != capture || s.matchingSyntheticBaseline(ctx, r, true) != nil {
				return nil, ErrSyntheticBaselineTransition
			}
			return r, nil
		}
	}
	return nil, nil
}

func (s *executionResourceScope) reserveSyntheticBaseline(ctx context.Context, r *syntheticBaselineExecutionResource) error {
	if s == nil || r == nil || r.self != r || r.binding == nil || r.binding.scope != s || r.relative != "" || r.anchor != nil || r.definition == nil {
		return ErrSyntheticBaselineTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.syntheticBaselineSource
	if c == nil || c.binding != r.binding || c.backend != r.backend || c.capture != r.capture || c.tools != r.tools || c.control != r.control || c.local(ctx) != nil || !s.open || s.syntheticClosing || s.failure != nil || s.resourceCount() >= maxExecutionResources || len(s.syntheticBaselines) >= 256 {
		return ErrSyntheticBaselineTransition
	}
	if err := s.checkOriginalOwner(ctx, nil, true, false); err != nil {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	for _, original := range s.syntheticBaselines {
		if original.mapping == r.mapping || original.definition.Mapping.PublicationID == r.definition.Mapping.PublicationID {
			return ErrSyntheticBaselineTransition // Caller may look up the same original mapping.
		}
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "sb-")
	if err != nil {
		return executionJournalError(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil {
		return executionJournalError(err)
	}
	r.relative, r.root, r.anchor = relative, filepath.Join(s.root, relative), anchor
	if r.local(ctx) != nil {
		return ErrSyntheticBaselineTransition
	}
	for _, path := range []string{r.root, filepath.Dir(r.root), s.root} {
		opened, err := openJournalDirectory(path)
		if err != nil {
			return executionJournalError(err)
		}
		err = errors.Join(syncDataplaneJournalDirectory(opened), opened.Close())
		if err != nil {
			return executionJournalError(err)
		}
	}
	if s.syntheticBaselines == nil {
		s.syntheticBaselines = make(map[string]*syntheticBaselineExecutionResource)
	}
	id := filepath.Base(relative)
	s.syntheticBaselines[id] = r
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: id, Kind: "synthetic-baseline", State: "prepared", Phase: "planned",
		Generation: r.effects.Generation, EffectsDigest: r.digest, SyntheticBaseline: cloneExecutionSyntheticBaselineDefinition(r.definition)})
	return s.persist() // Original durable planned intent precedes COMMON effects.
}

// Caller holds s.mu. This performs no provider/tool/control/capture callback.
func (s *executionResourceScope) matchingSyntheticBaseline(ctx context.Context, r *syntheticBaselineExecutionResource, forward bool) error {
	if r == nil || r.self != r || r.binding == nil || r.binding.scope != s || !s.open || s.syntheticClosing || s.failure != nil || r.local(ctx) != nil || s.syntheticBaselines[filepath.Base(r.relative)] != r {
		return ErrSyntheticBaselineTransition
	}
	c := s.syntheticBaselineSource
	if c == nil || c.binding != r.binding || c.backend != r.backend || c.capture != r.capture || c.tools != r.tools || c.control != r.control || c.local(ctx) != nil {
		return ErrSyntheticBaselineTransition
	}
	if err := s.checkOriginalOwner(ctx, nil, forward, false); err != nil {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	info, err := s.owned.Stat(r.relative)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(r.anchor, info) {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	for _, record := range s.execution.Resources {
		if record.ID == filepath.Base(r.relative) {
			if record.Kind != "synthetic-baseline" || record.State != "prepared" || record.Generation != r.effects.Generation || record.EffectsDigest != r.digest || !reflect.DeepEqual(record.SyntheticBaseline, r.definition) || validateExecutionSyntheticBaselineResource(*s.execution, record, record.SyntheticBaseline) != nil {
				return ErrSyntheticBaselineTransition
			}
			return nil
		}
	}
	return ErrSyntheticBaselineTransition
}

func (s *executionResourceScope) currentSyntheticBaseline(ctx context.Context, r *syntheticBaselineExecutionResource, forward bool) error {
	if s == nil {
		return ErrSyntheticBaselineTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matchingSyntheticBaseline(ctx, r, forward)
}

func (s *executionResourceScope) currentSyntheticBaselineStart(ctx context.Context, r *syntheticBaselineExecutionResource) error {
	return s.currentSyntheticBaseline(ctx, r, true)
}

func (s *executionResourceScope) recordSyntheticBaselinePhase(ctx context.Context, r *syntheticBaselineExecutionResource, phase string) error {
	if s == nil || phase != "baseline-prepared" && phase != "capture-ready" {
		return ErrSyntheticBaselineTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.matchingSyntheticBaseline(ctx, r, true); err != nil {
		return err
	}
	for i := range s.execution.Resources {
		record := &s.execution.Resources[i]
		if record.ID == filepath.Base(r.relative) {
			if record.Phase == phase {
				return nil // Same original owner/record already acknowledged this phase.
			}
			if phase == "baseline-prepared" && record.Phase != "planned" || phase == "capture-ready" && record.Phase != "baseline-prepared" {
				return ErrSyntheticBaselineTransition
			}
			record.Phase = phase
			return s.persist()
		}
	}
	return ErrSyntheticBaselineTransition
}
