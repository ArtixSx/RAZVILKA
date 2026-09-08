package config

import (
	"errors"
	"reflect"
	"strings"
	"time"
)

var ErrRevisionChanged = errors.New("configuration revision changed")

// ApplyNodeRouteWithRollback owns only one service's routing fields. Pending
// device scopes and all other desired changes remain untouched.
func (s *Store) ApplyNodeRouteWithRollback(id, route string, revision uint64) (func() error, error) {
	return s.applyNodeRouteWithRollback(id, route, nil, revision)
}

// ApplyNodeRouteScopeWithRollback also owns this service's explicit device
// selection. The route and scope become desired and applied in one commit.
func (s *Store) ApplyNodeRouteScopeWithRollback(id, route string, sources []string, revision uint64) (func() error, error) {
	normalized, err := NormalizeSources(sources)
	if err != nil {
		return nil, err
	}
	return s.applyNodeRouteWithRollback(id, route, &normalized, revision)
}

func (s *Store) applyNodeRouteWithRollback(id, route string, sources *[]string, revision uint64) (func() error, error) {
	if id == "" || len(route) != len("sing-box:node-")+64 || !strings.HasPrefix(route, "sing-box:node-") {
		return nil, errors.New("invalid node route")
	}
	for _, c := range strings.TrimPrefix(route, "sing-box:node-") {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, errors.New("invalid node route")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision || revision == ^uint64(0) || s.cfg.SafeMode {
		return nil, ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	desired, applied := s.cfg.Services[id], s.cfg.AppliedServices[id]
	if sources == nil && s.cfg.ServiceControl.Stopped {
		applied.Sources = AppliedSources(s.cfg, id)
	}
	desired.Enabled, desired.Mode, desired.Route = true, route, route
	applied.Enabled, applied.Mode, applied.Route = true, route, route
	if sources != nil {
		desired.Sources = append([]string(nil), (*sources)...)
		applied.Sources = append([]string(nil), (*sources)...)
	}
	s.cfg.Services[id], s.cfg.AppliedServices[id] = desired, applied
	clearServiceStopAfterManualApply(&s.cfg)
	fenceServicePolicy(&s.cfg, id, route, applied.Sources)
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
