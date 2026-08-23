package smartroute

import (
	"path/filepath"
	"testing"
	"time"

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
		{ServiceID: "youtube", Route: "usque", Status: "pass", LatencyMS: 40, RouteConfirmed: true, EvidenceSource: "explicit-socks5", CheckedAt: now.Format(time.RFC3339)},
		{ServiceID: "youtube", Route: "warp-wg", Status: "pass", LatencyMS: 80, RouteConfirmed: false, CheckedAt: now.Format(time.RFC3339)},
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
}

func TestHysteresisCooldownAndConfirmedFailover(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "usque", Status: "pass", LatencyMS: 20, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	decisions, _ := m.Observe([]testlab.Result{{ServiceID: "svc", Route: "direct", Status: "pass", LatencyMS: 10, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
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
	_, _ = m.Observe([]testlab.Result{{ServiceID: "svc", Route: "direct", Status: "pass", RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	m.now = func() time.Time { return now.Add(25 * time.Hour) }
	if got := m.Suggest("svc", "warp-wg"); got != "warp-wg" {
		t.Fatalf("expired evidence must fall back, got %q", got)
	}
}
