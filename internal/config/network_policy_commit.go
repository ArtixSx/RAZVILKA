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
	next, err := ReviewedNetworkPolicyCommitImage(expected, applied, services, time.Now())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.cfg, expected) {
		return nil, ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	s.cfg = next
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

// ReviewedNetworkPolicyCommitImage constructs the exact sanctioned postimage
// without IO or effect permission. A consumer can compare it with the actual
// committed image using that image's separately verified application time.
// The Store uses this same function, so normalization and policy fences cannot
// drift from a caller's full postcondition check.
func ReviewedNetworkPolicyCommitImage(expected Config, applied *NetworkPolicy, services map[string]ServiceState, appliedAt time.Time) (Config, error) {
	if err := ValidateAppliedNetworkPolicy(applied); err != nil {
		return Config{}, err
	}
	if appliedAt.IsZero() || expected.Revision == ^uint64(0) || expected.SafeMode || expected.ServiceControl.Stopped {
		return Config{}, ErrRevisionChanged
	}
	wanted := CloneNetworkPolicy(expected.NetworkPolicy)
	if wanted != nil && wanted.Traffic.DefaultRoute == DefaultRouteAuto && applied != nil {
		wanted.Traffic.DefaultRoute = applied.Traffic.DefaultRoute
	}
	if !reflect.DeepEqual(wanted, applied) {
		return Config{}, ErrRevisionChanged
	}
	nextServices := make(map[string]ServiceState, len(services))
	for id, state := range services {
		if id == "" {
			return Config{}, ErrRevisionChanged
		}
		normalized := normalizeState(state)
		sources, err := NormalizeSources(normalized.Sources)
		if err != nil || !slices.Equal(sources, normalized.Sources) {
			return Config{}, ErrRevisionChanged
		}
		normalized.Sources = slices.Clone(sources)
		nextServices[id] = normalized
	}
	next := cloneConfig(expected)
	next.AppliedNetworkPolicy = CloneNetworkPolicy(applied)
	next.AppliedServices = nextServices
	for id, state := range nextServices {
		if !reflect.DeepEqual(expected.AppliedServices[id], state) {
			fenceServicePolicy(&next, id, state.Route, state.Sources)
		}
	}
	for id := range expected.AppliedServices {
		if _, retained := nextServices[id]; !retained {
			fenceServicePolicy(&next, id, "direct", nil)
		}
	}
	next.Revision++
	// Only this exact sanctioned unchanged-policy CAS may advance an approved
	// intent's current config revision. Its immutable approval digest is stable.
	if CurrentDefaultRouteConsent(expected) {
		next.DefaultRouteConsent.ConfigRevision = next.Revision
	}
	next.AppliedRevision = next.Revision
	next.LastAppliedAt = appliedAt.UTC().Format(time.RFC3339)
	return next, nil
}
