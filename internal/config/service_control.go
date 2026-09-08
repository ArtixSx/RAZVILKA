package config

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"
)

const MaxScheduledServices = 64

type ServiceCheckSchedule struct {
	Enabled         bool     `json:"enabled"`
	IntervalSeconds int      `json:"interval_seconds"`
	ServiceIDs      []string `json:"service_ids"`
}

// Runtime snapshots contain only the previously applied choices, never desired
// editor changes. Empty mode preserves the legacy explicit group opt-in.
type ServiceControl struct {
	Mode              string                  `json:"mode,omitempty"`
	Schedule          ServiceCheckSchedule    `json:"schedule"`
	Stopped           bool                    `json:"stopped,omitempty"`
	SuspendedServices map[string]ServiceState `json:"suspended_services,omitempty"`
	SuspendedRoutes   map[string]string       `json:"suspended_routes,omitempty"`
}

func (c ServiceControl) EffectiveMode() string {
	if c.Mode == "manual" {
		return "manual"
	}
	return "auto"
}

// An explicit reviewed live apply while stopped starts only its reviewed plan.
// Other suspended choices remain in desired settings, never silently resumed.
// Caller retains the complete previous Config for transactional rollback.
func clearServiceStopAfterManualApply(cfg *Config) {
	if !cfg.ServiceControl.Stopped {
		return
	}
	for _, state := range cfg.AppliedServices {
		if state.Enabled {
			cfg.ServiceControl.Stopped = false
			cfg.ServiceControl.SuspendedServices, cfg.ServiceControl.SuspendedRoutes = nil, nil
			return
		}
	}
}

// AppliedSources retains the former applied client boundary while routes are
// stopped. A route-only edit must not reinterpret an empty live map as all LAN.
func AppliedSources(cfg Config, id string) []string {
	if cfg.ServiceControl.Stopped {
		if state, ok := cfg.ServiceControl.SuspendedServices[id]; ok {
			return slices.Clone(state.Sources)
		}
	}
	return slices.Clone(cfg.AppliedServices[id].Sources)
}

func cloneServiceControl(c ServiceControl) ServiceControl {
	c.Schedule.ServiceIDs = slices.Clone(c.Schedule.ServiceIDs)
	if c.SuspendedServices != nil {
		c.SuspendedServices = cloneServices(c.SuspendedServices)
	}
	if c.SuspendedRoutes != nil {
		m := make(map[string]string, len(c.SuspendedRoutes))
		for id, route := range c.SuspendedRoutes {
			m[id] = route
		}
		c.SuspendedRoutes = m
	}
	return c
}

func validateServiceControl(c ServiceControl) error {
	if c.Mode != "" && c.Mode != "auto" && c.Mode != "manual" {
		return errors.New("invalid service control mode")
	}
	s := c.Schedule
	if s.IntervalSeconds != 0 && (s.IntervalSeconds < 60 || s.IntervalSeconds > 86400) || len(s.ServiceIDs) > MaxScheduledServices || s.Enabled && (len(s.ServiceIDs) == 0 || s.IntervalSeconds < 60) {
		return errors.New("invalid service check schedule")
	}
	seen := map[string]bool{}
	for _, id := range s.ServiceIDs {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "/\\\x00\r\n") || seen[id] {
			return errors.New("invalid scheduled service")
		}
		seen[id] = true
	}
	if !c.Stopped && (len(c.SuspendedServices) != 0 || len(c.SuspendedRoutes) != 0) || len(c.SuspendedServices) > 128 || len(c.SuspendedRoutes) > len(c.SuspendedServices) {
		return errors.New("invalid suspended routes")
	}
	for id, state := range c.SuspendedServices {
		if id == "" || len(id) > 128 || state.Enabled && c.SuspendedRoutes[id] == "" || len(c.SuspendedRoutes[id]) > 128 {
			return errors.New("invalid suspended service")
		}
		if _, err := NormalizeSources(state.Sources); err != nil {
			return err
		}
	}
	for id := range c.SuspendedRoutes {
		if state, ok := c.SuspendedServices[id]; !ok || !state.Enabled {
			return errors.New("invalid suspended route binding")
		}
	}
	return nil
}

func (s *Store) UpdateServiceControl(mode *string, schedule *ServiceCheckSchedule, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision || revision == ^uint64(0) {
		return ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	next := cloneServiceControl(s.cfg.ServiceControl)
	if mode != nil {
		next.Mode = *mode
	}
	if schedule != nil {
		next.Schedule = *schedule
		next.Schedule.ServiceIDs = slices.Clone(schedule.ServiceIDs)
	}
	if err := validateServiceControl(next); err != nil {
		return err
	}
	s.cfg.ServiceControl = next
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

// CommitServiceRuntime changes only applied state after the owned dataplane
// transaction succeeds. Desired services, policies and all editor files survive.
func (s *Store) CommitServiceRuntime(stopped bool, resolved map[string]string, revision uint64) (func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision || revision == ^uint64(0) {
		return nil, ErrRevisionChanged
	}
	if s.cfg.SafeMode || s.cfg.ServiceControl.Stopped == stopped {
		return nil, errors.New("runtime transition is unavailable")
	}
	previous := cloneConfig(s.cfg)
	c := cloneServiceControl(s.cfg.ServiceControl)
	if stopped {
		c.SuspendedServices = cloneServices(s.cfg.AppliedServices)
		c.SuspendedRoutes = map[string]string{}
		for id, state := range s.cfg.AppliedServices {
			if state.Enabled {
				c.SuspendedServices[id] = state
				c.SuspendedRoutes[id] = resolved[id]
			}
		}
		if len(c.SuspendedRoutes) == 0 {
			return nil, errors.New("no applied routes to stop")
		}
		s.cfg.AppliedServices = map[string]ServiceState{}
	} else {
		if len(c.SuspendedServices) == 0 || len(s.cfg.AppliedServices) != 0 {
			return nil, errors.New("no unchanged resume snapshot")
		}
		s.cfg.AppliedServices = cloneServices(c.SuspendedServices)
		c.SuspendedServices, c.SuspendedRoutes = nil, nil
	}
	c.Stopped = stopped
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
