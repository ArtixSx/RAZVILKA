package config

import (
	"errors"
	"reflect"
	"time"
)

// CommitServiceRecoveryStop is only the configuration publication of an
// explicitly reviewed, independently inactive degraded NFQWS2 Stop transaction.
// Caller must retain the Manager transaction and complete ownership review.
// The complete old image (including SafeMode) is restored by the normal undo.
func (s *Store) CommitServiceRecoveryStop(expected Config, resolved map[string]string) (func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.cfg, expected) || !s.cfg.SafeMode || s.cfg.ServiceControl.Stopped || s.cfg.Revision == ^uint64(0) {
		return nil, ErrRevisionChanged
	}
	count := 0
	for id, state := range s.cfg.AppliedServices {
		if state.Enabled {
			count++
			if resolved[id] != "nfqws2" {
				return nil, errors.New("recovery stop requires exact NFQWS2 routes")
			}
		}
	}
	if count == 0 || len(resolved) != count {
		return nil, errors.New("recovery stop scope mismatch")
	}
	previous := cloneConfig(s.cfg)
	s.cfg.SafeMode = false
	c := cloneServiceControl(s.cfg.ServiceControl)
	c.SuspendedServices = cloneServices(s.cfg.AppliedServices)
	c.SuspendedRoutes = map[string]string{}
	for id, state := range s.cfg.AppliedServices {
		if state.Enabled {
			c.SuspendedRoutes[id] = resolved[id]
		}
	}
	s.cfg.AppliedServices = map[string]ServiceState{}
	c.Stopped = true
	if err := validateServiceControl(c); err != nil {
		s.cfg = previous
		return nil, err
	}
	s.cfg.ServiceControl = c
	s.cfg.Revision++
	s.cfg.AppliedRevision = s.cfg.Revision
	s.cfg.LastAppliedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return nil, err
	}
	committed := cloneConfig(s.cfg)
	return func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !reflect.DeepEqual(s.cfg, committed) {
			return ErrRevisionChanged
		}
		s.cfg = cloneConfig(previous)
		if err := s.saveLocked(); err != nil {
			s.cfg = cloneConfig(committed)
			return err
		}
		return nil
	}, nil
}
