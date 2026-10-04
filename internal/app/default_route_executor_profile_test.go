package app

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestDefaultRouteNamedProfileRevisionBoundBeforeEffects(t *testing.T) {
	cfg, snapshot, now := defaultRouteFixture()
	c, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := defaultRouteExecutorFixtureConfig(t, cfg, snapshot)
	input := e.input(c, e.app.Store.Get())
	for _, r := range input.Routes {
		revision, err := dataplane.FrozenWireGuardProfileRevision(r)
		if err != nil || revision != snapshot.Paths["default"].WireGuardProfileRevision {
			t.Fatal("input lost exact profile revision", err)
		}
	}
	changed := defaultRouteCloneInput(input)
	changed.Routes[0].WireGuardProfileRevision = strings.Repeat("7", 64)
	if defaultRouteBoundInput(input, changed) {
		t.Fatal("binding could substitute a new profile")
	}
	path := snapshot.Paths["default"]
	path.WireGuardProfileRevision = ""
	snapshot.Paths["default"] = path
	if _, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now); err == nil {
		t.Fatal("named profile had no exact revision")
	}
	path.WireGuardProfileRevision = strings.Repeat("7", 64)
	snapshot.Paths["default"] = path
	next, err := CompileDefaultRoutePolicy(cfg, snapshot, nil, now)
	if err != nil || next.Digest() == c.Digest() {
		t.Fatal("profile revision missing from compiler identity", err)
	}
}
