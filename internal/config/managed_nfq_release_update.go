package config

import "errors"

var ErrManagedNFQReleaseUpdate = errors.New("MANAGED_NFQWS_UPDATE_REQUIRES_STOP: новое применение управляемого NFQWS2 отключено в этом выпуске; остановите текущий маршрут средствами прежней версии и повторите обновление; автоматическое возобновление не выполняется")

// CheckManagedNFQReleaseUpdate is a pure compatibility refusal on an inspected
// configuration, not evidence that processes/rules are absent. Existing update
// ownership and pending-recovery checks remain mandatory. In particular Stop's
// suspended choices are not live applied routes and are never resumed here.
func CheckManagedNFQReleaseUpdate(cfg Config) error {
	if cfg.NetworkPolicy == nil && cfg.AppliedNetworkPolicy == nil {
		return nil // The independent legacy standalone NFQ path is unchanged.
	}
	for _, state := range cfg.AppliedServices {
		if !state.Enabled {
			continue
		}
		route := state.Route
		if route == "" {
			route = state.Mode
		}
		switch route {
		case "nfqws2", "auto", "":
			// A stopped flag cannot override contradictory enabled applied data.
			// Missing/null applied maps are normalized by Inspect from the draft.
			return ErrManagedNFQReleaseUpdate
		}
	}
	return nil
}
