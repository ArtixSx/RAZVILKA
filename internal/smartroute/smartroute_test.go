package smartroute

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestObserveChoosesConfirmedRouteAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smart-route.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	decisions, err := m.Observe([]testlab.Result{
		{ServiceID: "youtube", Route: "direct", Status: "fail", RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)},
		{ServiceID: "youtube", Route: "usque", Status: "pass", HTTPStatus: 204, LatencyMS: 40, RouteConfirmed: true, EvidenceSource: "explicit-socks5", CheckedAt: now.Format(time.RFC3339)},
		{ServiceID: "youtube", Route: "warp-wg", Status: "pass", HTTPStatus: 204, LatencyMS: 80, RouteConfirmed: false, CheckedAt: now.Format(time.RFC3339)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Selected != "usque" || !decisions[0].Changed {
		t.Fatalf("unexpected decisions: %+v", decisions)
	}
	if got := m.Suggest("youtube", "nfqws2"); got != "usque" {
		t.Fatalf("suggest=%q", got)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.now = m.now
	if got := reloaded.Suggest("youtube", "direct"); got != "usque" {
		t.Fatalf("reloaded suggest=%q", got)
	}
	if _, exists := reloaded.Snapshot().Services["youtube"].Evidence["warp-wg"]; exists {
		t.Fatal("unconfirmed route evidence must not be stored")
	}
	if got := reloaded.Snapshot().Services["youtube"].Evidence["usque"].Level; got != evidence.Service {
		t.Fatalf("stored evidence level = %q, want %q", got, evidence.Service)
	}
}

func TestObserveRejectsDeclaredRuntimeOnlyEvidence(t *testing.T) {
	m, _ := New("")
	decisions, err := m.Observe([]testlab.Result{{ServiceID: "svc", Route: "nfqws2", Status: "pass", RouteConfirmed: true, EvidenceLevel: evidence.Runtime, CheckedAt: time.Now().UTC().Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 0 || len(m.Snapshot().Services) != 0 {
		t.Fatalf("runtime-only evidence armed Smart Route: decisions=%+v state=%+v", decisions, m.Snapshot())
	}
}

func TestObserveNeverSelectsPolicyBlockedService(t *testing.T) {
	m, _ := New("")
	now := time.Now().UTC()
	decisions, err := m.Observe([]testlab.Result{{ServiceID: "telegram", Route: "warp-wg", Status: "partial", HTTPStatus: 451, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	got := m.Suggest("telegram", "direct")
	if len(decisions) != 1 || decisions[0].Selected != "" || got != "direct" {
		t.Fatalf("blocked response armed Smart Route: decisions=%+v snapshot=%+v", decisions, m.Snapshot())
	}
	stored := m.Snapshot().Services["telegram"].Evidence["warp-wg"]
	if stored.Level != evidence.Route || stored.Outcome != evidence.OutcomeServiceBlocked || stored.FreshUntil == "" {
		t.Fatalf("blocked evidence was not preserved honestly: %+v", stored)
	}
}

func TestMisroutedObservationRevokesPreviousSuccess(t *testing.T) {
	m, _ := New("")
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now}})
	if got := m.Suggest("svc", "direct"); got != "sing-box" {
		t.Fatalf("initial route=%s", got)
	}
	_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 200, RouteConfirmed: true, CheckedAt: now, ExpectedRoutePathID: "isolated:sing-box", ObservedRoutePathID: "isolated:direct"}})
	if got := m.Suggest("svc", "direct"); got != "direct" {
		t.Fatalf("misrouted success stayed armed: %s", got)
	}
}

func TestRouteOwnershipFailureRevokesPreviousSuccess(t *testing.T) {
	for _, status := range []string{"pass", "fail", "partial"} {
		t.Run(status, func(t *testing.T) {
			m, _ := New("")
			now := time.Now().UTC().Format(time.RFC3339)
			_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now}})
			if got := m.Suggest("svc", "direct"); got != "sing-box" {
				t.Fatalf("initial=%s", got)
			}
			_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: status, HTTPStatus: 200, RouteProofError: "route-runtime-changed", CheckedAt: now}})
			if got := m.Suggest("svc", "direct"); got != "direct" {
				t.Fatalf("stale proof used: %s", got)
			}
		})
	}
}

func TestInconclusiveHighScoreCannotHideWorkingCandidate(t *testing.T) {
	m, _ := New("")
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = m.Observe([]testlab.Result{
		{ServiceID: "svc", Route: "direct", Status: "pass", RouteConfirmed: true, CheckedAt: now},
		{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now},
	})
	if got := m.Suggest("svc", "nfqws2"); got != "sing-box" {
		t.Fatalf("inconclusive result hid working route: %s", got)
	}
}

func TestHysteresisCooldownAndConfirmedFailover(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "usque", Status: "pass", HTTPStatus: 204, LatencyMS: 20, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	decisions, _ := m.Observe([]testlab.Result{{ServiceID: "svc", Route: "direct", Status: "pass", HTTPStatus: 204, LatencyMS: 10, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if decisions[0].Selected != "usque" || decisions[0].Reason != "switch-cooldown-active" {
		t.Fatalf("cooldown should retain route: %+v", decisions[0])
	}
	decisions, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "usque", Status: "fail", RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if decisions[0].Selected != "direct" || decisions[0].Reason != "confirmed-failover" {
		t.Fatalf("confirmed failure should bypass cooldown: %+v", decisions[0])
	}
}

func TestSuggestionExpires(t *testing.T) {
	m, _ := New("")
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "direct", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	m.now = func() time.Time { return now.Add(25 * time.Hour) }
	if got := m.Suggest("svc", "warp-wg"); got != "warp-wg" {
		t.Fatalf("expired evidence must fall back, got %q", got)
	}
}

func TestEvidenceIsScopedToCurrentNetworkProfile(t *testing.T) {
	m, _ := New("")
	profile := "wan-a"
	m.Profile = func() string { return profile }
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, err := m.Observe([]testlab.Result{{ServiceID: "telegram", Route: "warp-wg", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Suggest("telegram", "nfqws2"); got != "warp-wg" {
		t.Fatalf("same profile suggestion = %q", got)
	}
	profile = "wan-b"
	if got := m.Suggest("telegram", "nfqws2"); got != "nfqws2" {
		t.Fatalf("evidence leaked into another WAN profile: %q", got)
	}
	if got := m.Snapshot().NetworkProfile; got != "wan-b" {
		t.Fatalf("snapshot profile = %q", got)
	}
	profile = "wan-a"
	if got := m.Suggest("telegram", "direct"); got != "warp-wg" {
		t.Fatalf("returning to known profile lost evidence: %q", got)
	}
}

func TestSchemaOneMigratesWithoutArmingCurrentNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smart-route.json")
	old := `{"schema":1,"services":{"telegram":{"selected_route":"warp-wg","evidence":{"warp-wg":{"route":"warp-wg","status":"pass","score":90,"evidence_level":"service-confirmed","confirmed_at":"2026-08-14T12:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Profile = func() string { return "wan-current" }
	m.now = func() time.Time { return time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC) }
	if got := m.Suggest("telegram", "direct"); got != "direct" {
		t.Fatalf("legacy unscoped evidence armed current network: %q", got)
	}
	if m.Snapshot().KnownProfiles != 1 {
		t.Fatalf("legacy profile was not preserved: %+v", m.Snapshot())
	}
}
