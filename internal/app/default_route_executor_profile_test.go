package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestDefaultRouteNamedProfileRevisionBoundBeforeEffects(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, defaultRouteListedRoutes(), now)
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := defaultRouteExecutorFixtureConfig(t, cfg, snapshot)
	input := e.input(c, e.app.Store.Get())
	for _, r := range input.Routes {
		revision, err := dataplane.FrozenWireGuardProfileRevision(r)
		if err != nil || revision != snapshot.Paths["listed"].WireGuardProfileRevision {
			t.Fatal("input lost exact profile revision", err)
		}
	}
	changed := defaultRouteCloneInput(input)
	changed.Routes[0].WireGuardProfileRevision = strings.Repeat("7", 64)
	if defaultRouteBoundInput(input, changed) {
		t.Fatal("binding could substitute a new profile")
	}
	path := snapshot.Paths["listed"]
	path.WireGuardProfileRevision = ""
	snapshot.Paths["listed"] = path
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, defaultRouteListedRoutes(), now); err == nil {
		t.Fatal("named profile had no exact revision")
	}
	path.WireGuardProfileRevision = strings.Repeat("7", 64)
	snapshot.Paths["listed"] = path
	routes := defaultRouteListedRoutes()
	routes[0].WireGuardProfileRevision = path.WireGuardProfileRevision
	next, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now)
	if err != nil || next.Digest() == c.Digest() {
		t.Fatal("profile revision missing from compiler identity", err)
	}
}

func TestDefaultRouteNamedServiceRevisionBindsDesiredConfig(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	routes := defaultRouteOverrideFixture(&cfg, &snapshot)
	revision := strings.Repeat("6", 64)
	state := cfg.Services["service"]
	state.Route, state.WireGuardProfileRevision = "wireguard:service-profile", revision
	cfg.Services["service"] = state
	path := snapshot.Paths["service"]
	path.Selected, path.Resolved, path.WireGuardProfileRevision = state.Route, state.Route, revision
	snapshot.Paths["service"] = path
	routes[0].Selected, routes[0].Resolved, routes[0].WireGuardProfileRevision = state.Route, state.Route, revision
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); err != nil {
		t.Fatal("exact desired/path/route revision refused", err)
	}
	for _, desiredRevision := range []string{"", strings.Repeat("7", 64)} {
		cfg.Services["service"] = config.ServiceState{Enabled: true, Route: state.Route, Sources: state.Sources, WireGuardProfileRevision: desiredRevision}
		if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); !errors.Is(err, dataplane.ErrReviewChanged) {
			t.Fatal("fresh runtime snapshot replaced desired config profile binding", desiredRevision, err)
		}
	}
	// Auto keeps its desired intent; only an explicitly selected named profile
	// has a named config binding. Its trusted resolved path still carries the
	// exact profile revision, which must match the compiled route.
	state.Route, state.WireGuardProfileRevision = "auto", ""
	cfg.Services["service"] = state
	path.Selected, routes[0].Selected = "auto", "auto"
	snapshot.Paths["service"] = path
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, routes, now); err != nil {
		t.Fatal("auto intent required an unrelated explicit config selection", err)
	}
}
