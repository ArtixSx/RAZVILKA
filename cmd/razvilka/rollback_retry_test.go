package main

import (
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"testing"
)

func TestRollbackSettingsMatchAppliedScopeWithoutConsumingDraft(t *testing.T) {
	p := dataplane.Plan{Revision: 4, Routes: []dataplane.Route{{ServiceID: "discord", Selected: "sing-box:private", Sources: []string{"192.168.1.40/32"}}}}
	base := func() config.Config {
		return config.Config{Revision: 5, AppliedRevision: 4, AppliedServices: map[string]config.ServiceState{"discord": {Enabled: true, Route: "sing-box:private", Sources: []string{"192.168.1.40/32"}}}, Services: map[string]config.ServiceState{"discord": {Enabled: false, Route: "direct"}}}
	}
	if !rollbackAppliedSettingsMatch(base(), p) {
		t.Fatal("pending draft prevented restoration of applied scope")
	}
	for _, mode := range []string{"revision", "disabled", "route", "device", "extra-service", "stopped", "safe-mode"} {
		cfg := base()
		s := cfg.AppliedServices["discord"]
		switch mode {
		case "revision":
			cfg.AppliedRevision++
		case "disabled":
			s.Enabled = false
		case "route":
			s.Route = "direct"
		case "device":
			s.Sources = nil
		case "extra-service":
			cfg.AppliedServices["other"] = config.ServiceState{Enabled: true, Route: "direct"}
		case "stopped":
			cfg.ServiceControl.Stopped = true
		case "safe-mode":
			cfg.SafeMode = true
		}
		cfg.AppliedServices["discord"] = s
		if rollbackAppliedSettingsMatch(cfg, p) {
			t.Fatal("accepted changed", mode)
		}
	}
}

func TestCloseRollbackSettingsIgnoreOnlySafeMode(t *testing.T) {
	p := dataplane.Plan{Revision: 4, Routes: []dataplane.Route{{ServiceID: "discord", Selected: "sing-box:private", Sources: []string{"192.168.1.40/32"}}}}
	cfg := config.Config{Revision: 5, AppliedRevision: 4, SafeMode: true, AppliedServices: map[string]config.ServiceState{"discord": {Enabled: true, Route: "sing-box:private", Sources: []string{"192.168.1.40/32"}}}}
	if rollbackAppliedSettingsMatch(cfg, p) || !closeRollbackSettingsMatch(cfg, p) {
		t.Fatal("explicit recovery must accept the Safe Mode a fenced boot enabled; the panel's own check must not")
	}
	if !cfg.SafeMode {
		t.Fatal("close check changed the caller's settings")
	}
	for _, mode := range []string{"revision", "stopped", "route"} {
		changed := cfg
		changed.AppliedServices = map[string]config.ServiceState{"discord": cfg.AppliedServices["discord"]}
		switch mode {
		case "revision":
			changed.AppliedRevision++
		case "stopped":
			changed.ServiceControl.Stopped = true
		case "route":
			changed.AppliedServices["discord"] = config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.40/32"}}
		}
		if closeRollbackSettingsMatch(changed, p) {
			t.Fatal("close accepted changed", mode)
		}
	}
}

// A current home-network intent closes the legacy rollback comparison. Saved
// whole-network site exclusions do not: a rollback returns the last applied
// state, and the saved list stays a pending change.
func TestLegacyRollbackRefusesCurrentListIntentButNotSavedSiteExclusions(t *testing.T) {
	previous := dataplane.Plan{Revision: 4, Routes: []dataplane.Route{{ServiceID: "discord", Selected: "sing-box:private", Sources: []string{"192.168.1.40/32"}}}}
	for _, target := range []config.ResourceMatch{{Kind: "service", Value: "discord"}, {Kind: "exact", Value: "discord.com"}, {Kind: "ip", Value: "203.0.113.40"}, {Kind: "cidr", Value: "203.0.113.0/24"}} {
		for _, storage := range []string{"inactive", "configured"} {
			t.Run(storage+"/"+target.Kind, func(t *testing.T) {
				cfg := config.Config{Revision: 5, AppliedRevision: 4, AppliedServices: map[string]config.ServiceState{"discord": {Enabled: true, Route: "sing-box:private", Sources: []string{"192.168.1.40/32"}}}}
				if !rollbackAppliedSettingsMatch(cfg, previous) {
					t.Fatal("fixture does not match the legacy plan")
				}
				exclusions := &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{target}}
				if storage == "inactive" {
					cfg.InactiveResourceExclusions = exclusions
				} else {
					cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}, Exclusions: exclusions}
				}
				if storage == "inactive" {
					if !rollbackAppliedSettingsMatch(cfg, previous) || !closeRollbackSettingsMatch(cfg, previous) {
						t.Fatal("saved site exclusions closed the return to the last applied state")
					}
					return
				}
				if rollbackAppliedSettingsMatch(cfg, previous) {
					t.Fatal("legacy service comparison authorized current unsupported list intent")
				}
				cfg.SafeMode = true
				if closeRollbackSettingsMatch(cfg, previous) {
					t.Fatal("recovery Safe Mode exception waived current list intent")
				}
				if exclusions.Revision != 1 || len(exclusions.Manual) != 1 || exclusions.Manual[0] != target || !cfg.SafeMode {
					t.Fatal("refusal changed saved intent")
				}
			})
		}
	}
}
