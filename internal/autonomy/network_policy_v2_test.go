package autonomy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func allInternetFixture(t *testing.T) (*config.NetworkPolicy, ScopeObservation, TrafficQuestion) {
	t.Helper()
	p, o, q, _ := scopeFixture()
	p.Schema = 2
	p.Traffic = config.TrafficSelection{Mode: "all_except", AllExceptAllowed: true, DefaultRoute: config.DefaultRouteAuto, Unavailable: "block"}
	q.Domain, q.ServiceID, q.ServiceSelected = "unknown-new-site.example", "", false
	q.DefaultCoverage = "supported"
	return p, o, q
}

func decideAt(t *testing.T, p *config.NetworkPolicy, o ScopeObservation, q TrafficQuestion) NetworkDecision {
	t.Helper()
	_, _, _, now := scopeFixture()
	return DecideNetworkPolicy(p, o, q, now)
}

// G03-T01: zero selected services; an unknown site and a literal IP use the
// default path, not BASE and not a "no services" error.
func TestAllInternetUnknownSiteAndDirectIPUseDefault(t *testing.T) {
	p, o, q := allInternetFixture(t)
	literal := TrafficQuestion{Client: q.Client, Address: netip.MustParseAddr("203.0.113.9"), DefaultCoverage: "supported"}
	for _, question := range []TrafficQuestion{q, literal} {
		d := decideAt(t, p, o, question)
		if d.Action != "bypass" || d.Reason != "DEFAULT_POLICY" || d.Target != "default" {
			t.Fatalf("unmatched destination left the default path: %+v", d)
		}
	}
}

// G03-T02: an override scoped to client A does not send client B to BASE; B
// continues through exclusions to the default path.
func TestAllInternetServiceScopeMissInheritsDefault(t *testing.T) {
	p, o, q := allInternetFixture(t)
	q.Domain, q.ServiceID, q.ServiceSelected = "discord.com", "discord", true
	q.ServiceSources = []string{"192.168.1.41/32"} // client A; q is client B
	d := decideAt(t, p, o, q)
	if d.Action != "bypass" || d.Reason != "DEFAULT_POLICY" || d.Target != "default" {
		t.Fatalf("scope miss did not inherit the default path: %+v", d)
	}
	q.ServiceSources = []string{"192.168.1.40/32"}
	if d := decideAt(t, p, o, q); d.Action != "bypass" || d.Reason != "SERVICE_OVERRIDE" || d.Target != "service" {
		t.Fatalf("matching client did not use its override: %+v", d)
	}
	// Exclusions still apply after a scope miss.
	p.Russian = config.RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 1, Digest: strings.Repeat("b", 64), ServiceIDs: []string{"discord"}}
	q.ServiceSources = []string{"192.168.1.41/32"}
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RU_CATALOG_DIRECT" {
		t.Fatalf("scope miss skipped the Russian exclusion: %+v", d)
	}
	// Legacy selected-services policies keep their original meaning.
	legacy, _, _, _ := scopeFixture()
	q.ServiceID = "other"
	if d := decideAt(t, legacy, o, q); d.Action != "base" || d.Reason != "SERVICE_SCOPE_MISMATCH" {
		t.Fatalf("schema 1 semantics changed: %+v", d)
	}
}

// Russian classification does not depend on whether the user selected the
// service; removing an override returns the site to the default path.
func TestAllInternetRussianExclusionIndependentOfSelection(t *testing.T) {
	p, o, q := allInternetFixture(t)
	p.Russian = config.RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 1, Digest: strings.Repeat("c", 64), ServiceIDs: []string{"bank"}}
	q.Domain, q.ServiceID = "bank.example", "bank"
	for _, selected := range []bool{false, true} {
		q.ServiceSelected = selected
		if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RU_CATALOG_DIRECT" {
			t.Fatalf("selected=%v bypassed the Russian exclusion: %+v", selected, d)
		}
	}
	q.ServiceID, q.ServiceSelected = "chatgpt", false
	if d := decideAt(t, p, o, q); d.Target != "default" || d.Action != "bypass" {
		t.Fatalf("removed override did not return to default: %+v", d)
	}
}

// G03-T06: a traffic class the default executor does not carry follows the
// explicit Unavailable policy and never becomes an implicit DIRECT.
func TestAllInternetUncoveredClassFollowsExplicitPolicy(t *testing.T) {
	for _, tt := range []struct{ unavailable, coverage, action, reason string }{
		{"block", "unsupported", "blocked", "DEFAULT_CLASS_BLOCKED"},
		{"block", "", "blocked", "DEFAULT_CLASS_BLOCKED"},
		{"base", "unknown", "base", "DEFAULT_CLASS_BASE"},
		{"retain", "unsupported", "unavailable", "DEFAULT_CLASS_UNAVAILABLE"},
	} {
		p, o, q := allInternetFixture(t)
		p.Traffic.Unavailable = tt.unavailable
		q.DefaultCoverage = tt.coverage
		if d := decideAt(t, p, o, q); d.Action != tt.action || d.Reason != tt.reason || d.Target != "default" {
			t.Fatalf("%+v: got %+v", tt, d)
		}
	}
	// A service override is not governed by the default path's coverage.
	p, o, q := allInternetFixture(t)
	q.DefaultCoverage = "unsupported"
	q.ServiceID, q.ServiceSelected = "youtube", true
	if d := decideAt(t, p, o, q); d.Action != "bypass" || d.Target != "service" {
		t.Fatalf("service override blocked by default coverage: %+v", d)
	}
}

// Device exclusions and mandatory direct rules apply before any path.
func TestAllInternetExclusionsPrecedeDefault(t *testing.T) {
	p, o, q := allInternetFixture(t)
	q.Client.MAC = o.Devices[0].MAC // excluded laptop
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "DEVICE_EXCLUDED" || d.Target != "" {
		t.Fatalf("excluded device reached a path: %+v", d)
	}
	p, o, q = allInternetFixture(t)
	p.Rules = []config.NetworkRule{{ID: "keep-direct", Revision: 1, Kind: "exact", Value: "unknown-new-site.example", Action: "direct", Mandatory: true}}
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "MANUAL_DIRECT" {
		t.Fatalf("mandatory direct ignored: %+v", d)
	}
	p.Rules = []config.NetworkRule{{ID: "force", Revision: 1, Kind: "exact", Value: "unknown-new-site.example", Action: "bypass", Mandatory: true}}
	q.DefaultCoverage = "unsupported"
	if d := decideAt(t, p, o, q); d.Action != "blocked" || d.RuleID != "force" {
		t.Fatalf("manual bypass through an uncovered default path: %+v", d)
	}
}
