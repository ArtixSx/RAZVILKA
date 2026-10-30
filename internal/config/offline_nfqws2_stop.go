package config

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// ReviewedNFQWS2StopImage predicts only the configuration half of an explicit
// NFQWS2 Stop. The caller must independently prove runtime absence and retain
// its durable Stop fence. A timestamp frozen in that fence makes a crash after
// the config rename distinguishable from an unrelated configuration edit.
func ReviewedNFQWS2StopImage(before Config, resolved map[string]string, appliedAt time.Time) (Config, error) {
	if before.ServiceControl.Stopped || before.Revision == ^uint64(0) || appliedAt.IsZero() {
		return Config{}, ErrRevisionChanged
	}
	count := 0
	for id, state := range before.AppliedServices {
		if state.Enabled {
			count++
			if resolved[id] != "nfqws2" {
				return Config{}, errors.New("recovery stop requires exact NFQWS2 routes")
			}
		}
	}
	if count == 0 || len(resolved) != count {
		return Config{}, errors.New("recovery stop scope mismatch")
	}
	after := cloneConfig(before)
	after.SafeMode = false
	after.ServiceControl.SuspendedServices = cloneServices(before.AppliedServices)
	after.ServiceControl.SuspendedRoutes = make(map[string]string, count)
	for id, route := range resolved {
		after.ServiceControl.SuspendedRoutes[id] = route
	}
	after.ServiceControl.Stopped = true
	after.AppliedServices = map[string]ServiceState{}
	after.Revision++
	after.AppliedRevision = after.Revision
	after.LastAppliedAt = appliedAt.UTC().Format(time.RFC3339)
	if err := validateServiceControl(after.ServiceControl); err != nil {
		return Config{}, err
	}
	return after, nil
}

// CommitNFQWS2OfflineStop is the same exact Store CAS as recovery Stop, with
// the original offline intent's timestamp. It grants no native cleanup or
// publication authority. Only the offline coordinator calls this after its
// real empty Manager transaction and fresh original-source absence checks.
func (s *Store) CommitNFQWS2OfflineStop(ctx context.Context, expected Config, resolved map[string]string, appliedAt time.Time) (func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRevisionChanged
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, ErrRevisionChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !reflect.DeepEqual(s.cfg, expected) {
		return nil, ErrRevisionChanged
	}
	return s.commitNFQWS2StopLocked(expected, resolved, appliedAt)
}

func (s *Store) commitNFQWS2StopLocked(expected Config, resolved map[string]string, appliedAt time.Time) (func() error, error) {
	if !reflect.DeepEqual(s.cfg, expected) {
		return nil, ErrRevisionChanged
	}
	after, err := ReviewedNFQWS2StopImage(expected, resolved, appliedAt)
	if err != nil {
		return nil, err
	}
	previous := cloneConfig(s.cfg)
	s.cfg = after
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
