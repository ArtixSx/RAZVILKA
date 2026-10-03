package config

import (
	"reflect"
	"slices"
	"time"
)

// CommitNetworkPolicyWithRollback publishes a reviewed applied policy and the
// complete reviewed applied-service view. The editor and suspended runtime are
// preserved. Full preimage comparison also detects legacy same-revision edits;
// the ordinary file CAS binds the exact bytes observed by this Store.
func (s *Store) CommitNetworkPolicyWithRollback(expected Config, applied *NetworkPolicy, services map[string]ServiceState) (func() error, error) {
	if err := ValidateAppliedNetworkPolicy(applied); err != nil {
		return nil, err
	}
	if expected.Revision == ^uint64(0) || expected.SafeMode || expected.ServiceControl.Stopped {
		return nil, ErrRevisionChanged
	}
	wanted := CloneNetworkPolicy(expected.NetworkPolicy)
	if wanted != nil && wanted.Traffic.DefaultRoute == DefaultRouteAuto && applied != nil {
		wanted.Traffic.DefaultRoute = applied.Traffic.DefaultRoute
	}
	if !reflect.DeepEqual(wanted, applied) {
		return nil, ErrRevisionChanged
	}
	nextServices := make(map[string]ServiceState, len(services))
	for id, state := range services {
		if id == "" {
			return nil, ErrRevisionChanged
		}
		normalized := normalizeState(state)
		sources, err := NormalizeSources(normalized.Sources)
		if err != nil || !slices.Equal(sources, normalized.Sources) {
			return nil, ErrRevisionChanged
		}
		normalized.Sources = slices.Clone(sources)
		nextServices[id] = normalized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.cfg, expected) {
		return nil, ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	s.cfg.AppliedNetworkPolicy = CloneNetworkPolicy(applied)
	s.cfg.AppliedServices = nextServices
	for id, state := range nextServices {
		if !reflect.DeepEqual(previous.AppliedServices[id], state) {
			fenceServicePolicy(&s.cfg, id, state.Route, state.Sources)
		}
	}
	for id := range previous.AppliedServices {
		if _, retained := nextServices[id]; !retained {
			fenceServicePolicy(&s.cfg, id, "direct", nil)
		}
	}
	s.cfg.Revision++
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
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
		s.cfg = cloneConfig(previous)
		if err := s.saveLocked(); err != nil {
			s.cfg = cloneConfig(committed)
			return err
		}
		used = true
		return nil
	}, nil
}
