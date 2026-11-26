package config

import (
	"errors"
	"strings"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

var ErrWireGuardProfileBinding = errors.New("invalid reviewed WireGuard profile binding")

func validateConfigServiceBindings(cfg Config) error {
	for _, states := range []map[string]ServiceState{cfg.Services, cfg.AppliedServices, cfg.ServiceControl.SuspendedServices} {
		for _, state := range states {
			if err := validateServiceProfileBinding(state); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateServiceProfileBinding(state ServiceState) error {
	if state.WireGuardProfileRevision == "" {
		return nil // Legacy retained intent is readable, but not new Apply authority.
	}
	route := normalizeState(state).Route
	if !strings.HasPrefix(route, "wireguard:") || !wireguardprofile.ValidID(strings.TrimPrefix(route, "wireguard:")) ||
		len(state.WireGuardProfileRevision) != 64 || strings.Trim(state.WireGuardProfileRevision, "0123456789abcdef") != "" {
		return ErrWireGuardProfileBinding
	}
	return nil
}
