package config

import (
	"errors"
	"reflect"
	"time"
)

// ApplyAutonomyRouteWithRollback is the commit callback of the ordinary
// dataplane transaction, never an API endpoint. The App must hold exclusive
// admission, consent and fresh exact proof. It changes one service only.
func (s *Store) ApplyAutonomyRouteWithRollback(id, route string, sources []string, revision uint64) (func() error, error) {
	undo, _, err := s.ApplyAutonomyRouteReviewedWithRollback(id, route, sources, revision)
	return undo, err
}

// The additional receipt records only this actual Store publication and its
// original undo. It supplies no consent, node proof or effect admission.
func (s *Store) ApplyAutonomyRouteReviewedWithRollback(id, route string, sources []string, revision uint64) (func() error, *AutonomyRouteCommitReview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision || revision == ^uint64(0) || s.cfg.SafeMode || s.cfg.ServiceControl.Stopped || s.cfg.ServiceControl.EffectiveMode() == "manual" {
		return nil, nil, ErrRevisionChanged
	}
	before := cloneConfig(s.cfg)
	started := time.Now().UTC()
	next, err := ReviewedAutonomyRouteCommitImage(before, id, route, sources, started)
	if err != nil {
		return nil, nil, err
	}
	s.cfg = next
	if err = s.saveLocked(); err != nil {
		s.cfg = before
		return nil, nil, err
	}
	committed := cloneConfig(s.cfg)
	review := &AutonomyRouteCommitReview{store: s, before: before, after: committed, id: id, route: route, sources: append([]string(nil), sources...), started: started, finished: time.Now().UTC()}
	review.self = review
	review.phase.Store(autonomyRouteCommitted)
	used := false
	return func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if used {
			return nil
		}
		if !reflect.DeepEqual(s.cfg, committed) {
			return ErrRevisionChanged
		}
		s.cfg = cloneConfig(before)
		if e := s.saveLocked(); e != nil {
			s.cfg = cloneConfig(committed)
			return e
		}
		used = true
		review.phase.Store(autonomyRouteRestored)
		return nil
	}, review, nil
}

// ApplyAutonomyRemovalWithRollback is only called after staged, scoped removal
// has passed dataplane health. Foreign service drafts and policies are retained.
func (s *Store) ApplyAutonomyRemovalWithRollback(id string, deleteDefinition bool, revision uint64) (func() error, error) {
	if !policyIdentifier.MatchString(id) {
		return nil, errors.New("invalid service")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision || revision == ^uint64(0) || s.cfg.SafeMode || s.cfg.ServiceControl.Stopped || s.cfg.ServiceControl.EffectiveMode() == "manual" {
		return nil, ErrRevisionChanged
	}
	before := cloneConfig(s.cfg)
	if deleteDefinition {
		delete(s.cfg.Services, id)
		delete(s.cfg.AppliedServices, id)
		delete(s.cfg.ServicePolicies, id)
	} else {
		draft := s.cfg.Services[id]
		draft.Enabled = false
		s.cfg.Services[id] = draft
		applied := s.cfg.AppliedServices[id]
		applied.Enabled = false
		s.cfg.AppliedServices[id] = applied
		fenceServicePolicy(&s.cfg, id, "", nil)
	}
	s.cfg.Revision++
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	if e := s.saveLocked(); e != nil {
		s.cfg = before
		return nil, e
	}
	after := cloneConfig(s.cfg)
	used := false
	return func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if used {
			return nil
		}
		if !reflect.DeepEqual(s.cfg, after) {
			return ErrRevisionChanged
		}
		s.cfg = cloneConfig(before)
		if e := s.saveLocked(); e != nil {
			s.cfg = cloneConfig(after)
			return e
		}
		used = true
		return nil
	}, nil
}
