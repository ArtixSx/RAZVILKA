package config

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"
)

// ApplyAutonomyRouteWithRollback is the commit callback of the ordinary
// dataplane transaction, never an API endpoint. The App must hold exclusive
// admission, consent and fresh exact proof. It changes one service only.
func (s *Store) ApplyAutonomyRouteWithRollback(id, route string, sources []string, revision uint64) (func() error, error) {
	valid := slices.Contains([]string{"nfqws2", "usque", "warp-wg"}, route)
	if strings.HasPrefix(route, "sing-box:node-") {
		node := strings.TrimPrefix(route, "sing-box:")
		valid = validPolicyNode(node)
	}
	if !policyIdentifier.MatchString(id) || !valid {
		return nil, errors.New("invalid autonomous route")
	}
	normalized, err := NormalizeSources(sources)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision || revision == ^uint64(0) || s.cfg.SafeMode || s.cfg.ServiceControl.Stopped || s.cfg.ServiceControl.EffectiveMode() == "manual" {
		return nil, ErrRevisionChanged
	}
	before := cloneConfig(s.cfg)
	desired := s.cfg.Services[id]
	desired.Enabled = true
	desired.Route = route
	desired.Mode = route
	desired.Sources = normalized
	s.cfg.Services[id] = desired
	s.cfg.AppliedServices[id] = desired
	// Superseded manual/legacy group authority cannot run concurrently with the
	// separately enrolled manager. The new manager uses its own scoped consent.
	fenceServicePolicy(&s.cfg, id, route, normalized)
	s.cfg.Revision++
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	if err = s.saveLocked(); err != nil {
		s.cfg = before
		return nil, err
	}
	committed := cloneConfig(s.cfg)
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
		return nil
	}, nil
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
