package config

import "errors"

var ErrProxySidecar = errors.New("proxy_sidecar must be empty, sing-box or hev")

func ValidateProxySidecar(value string) error {
	if value != "" && value != "sing-box" && value != "hev" {
		return ErrProxySidecar
	}
	return nil
}
func EffectiveProxySidecar(value string) string {
	if value == "" {
		return "sing-box"
	}
	return value
}

// SetProxySidecar changes only the next boot choice, not any current adapter.
// The API must first obtain exclusive original-owner quiescence admission.
func (s *Store) SetProxySidecar(expectedRevision uint64, value string) error {
	if err := ValidateProxySidecar(value); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != expectedRevision {
		return ErrRevisionChanged
	}
	if s.cfg.ProxySidecar == value {
		return nil
	}
	before := cloneConfig(s.cfg)
	s.cfg.ProxySidecar = value
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = before
		return err
	}
	return nil
}
