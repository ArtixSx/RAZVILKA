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
