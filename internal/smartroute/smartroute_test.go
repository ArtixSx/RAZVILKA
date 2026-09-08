package smartroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

const (
	testProfileA = "wan-aaaaaaaaaaaa"
	testProfileB = "wan-bbbbbbbbbbbb"
)

func newScopedTestManager(path string) (*Manager, error) {
	m, err := New(path)
	if err == nil {
		m.Profile = func() string { return testProfileA }
	}
	return m, err
}

func acceptedResult(now time.Time) []testlab.Result {
	return []testlab.Result{{ServiceID: "svc", Route: "usque", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now.UTC().Format(time.RFC3339Nano)}}
}

func TestObserveChoosesConfirmedRouteAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smart-route.json")
	m, err := newScopedTestManager(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	decisions, err := m.ObserveForProfile(testProfileA, []testlab.Result{
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
	reloaded, err := newScopedTestManager(path)
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
	m, _ := newScopedTestManager("")
	decisions, err := m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "nfqws2", Status: "pass", RouteConfirmed: true, EvidenceLevel: evidence.Runtime, CheckedAt: time.Now().UTC().Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 0 || len(m.Snapshot().Services) != 0 {
		t.Fatalf("runtime-only evidence armed Smart Route: decisions=%+v state=%+v", decisions, m.Snapshot())
	}
}

func TestObserveNeverSelectsPolicyBlockedService(t *testing.T) {
	m, _ := newScopedTestManager("")
	now := time.Now().UTC()
	decisions, err := m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "telegram", Route: "warp-wg", Status: "partial", HTTPStatus: 451, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
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
	m, _ := newScopedTestManager("")
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now}})
	if got := m.Suggest("svc", "direct"); got != "sing-box" {
		t.Fatalf("initial route=%s", got)
	}
	_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 200, RouteConfirmed: true, CheckedAt: now, ExpectedRoutePathID: "isolated:sing-box", ObservedRoutePathID: "isolated:direct"}})
	if got := m.Suggest("svc", "direct"); got != "direct" {
		t.Fatalf("misrouted success stayed armed: %s", got)
	}
}

func TestRouteOwnershipFailureRevokesPreviousSuccess(t *testing.T) {
	for _, status := range []string{"pass", "fail", "partial"} {
		t.Run(status, func(t *testing.T) {
			m, _ := newScopedTestManager("")
			now := time.Now().UTC().Format(time.RFC3339)
			_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now}})
			if got := m.Suggest("svc", "direct"); got != "sing-box" {
				t.Fatalf("initial=%s", got)
			}
			_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "sing-box", Status: status, HTTPStatus: 200, RouteProofError: "route-runtime-changed", CheckedAt: now}})
			if got := m.Suggest("svc", "direct"); got != "direct" {
				t.Fatalf("stale proof used: %s", got)
			}
		})
	}
}

func TestInconclusiveHighScoreCannotHideWorkingCandidate(t *testing.T) {
	m, _ := newScopedTestManager("")
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{
		{ServiceID: "svc", Route: "direct", Status: "pass", RouteConfirmed: true, CheckedAt: now},
		{ServiceID: "svc", Route: "sing-box", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now},
	})
	if got := m.Suggest("svc", "nfqws2"); got != "sing-box" {
		t.Fatalf("inconclusive result hid working route: %s", got)
	}
}

func TestHysteresisCooldownAndConfirmedFailover(t *testing.T) {
	m, err := newScopedTestManager("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "usque", Status: "pass", HTTPStatus: 204, LatencyMS: 20, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	decisions, _ := m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "direct", Status: "pass", HTTPStatus: 204, LatencyMS: 10, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if decisions[0].Selected != "usque" || decisions[0].Reason != "switch-cooldown-active" {
		t.Fatalf("cooldown should retain route: %+v", decisions[0])
	}
	decisions, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "usque", Status: "fail", RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if decisions[0].Selected != "direct" || decisions[0].Reason != "confirmed-failover" {
		t.Fatalf("confirmed failure should bypass cooldown: %+v", decisions[0])
	}
}

func TestSuggestionExpires(t *testing.T) {
	m, _ := newScopedTestManager("")
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, _ = m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "svc", Route: "direct", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	m.now = func() time.Time { return now.Add(25 * time.Hour) }
	if got := m.Suggest("svc", "warp-wg"); got != "warp-wg" {
		t.Fatalf("expired evidence must fall back, got %q", got)
	}
}

func TestEvidenceIsScopedToCurrentNetworkProfile(t *testing.T) {
	m, _ := newScopedTestManager("")
	profile := testProfileA
	m.Profile = func() string { return profile }
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	_, err := m.ObserveForProfile(testProfileA, []testlab.Result{{ServiceID: "telegram", Route: "warp-wg", Status: "pass", HTTPStatus: 204, RouteConfirmed: true, CheckedAt: now.Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Suggest("telegram", "nfqws2"); got != "warp-wg" {
		t.Fatalf("same profile suggestion = %q", got)
	}
	profile = testProfileB
	if got := m.Suggest("telegram", "nfqws2"); got != "nfqws2" {
		t.Fatalf("evidence leaked into another WAN profile: %q", got)
	}
	if got := m.Snapshot().NetworkProfile; got != testProfileB {
		t.Fatalf("snapshot profile = %q", got)
	}
	profile = testProfileA
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
	m, err := newScopedTestManager(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Profile = func() string { return testProfileA }
	m.now = func() time.Time { return time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC) }
	if got := m.Suggest("telegram", "direct"); got != "direct" {
		t.Fatalf("legacy unscoped evidence armed current network: %q", got)
	}
	if m.Snapshot().KnownProfiles != 1 {
		t.Fatalf("legacy profile was not preserved: %+v", m.Snapshot())
	}
}

func TestUnscopedObservationNeverGrantsAuthority(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-profile-provider", true: "known-profile-provider"}[configured], func(t *testing.T) {
			m, _ := New(filepath.Join(t.TempDir(), "smart-route.json"))
			if configured {
				m.Profile = func() string { return testProfileA }
			}
			decisions, err := m.Observe(acceptedResult(time.Now().UTC()))
			if !errors.Is(err, ErrUnscopedObservation) || len(decisions) != 0 || len(m.doc.Profiles) != 0 {
				t.Fatalf("unscoped observation granted authority: decisions=%+v err=%v profiles=%+v", decisions, err, m.doc.Profiles)
			}
			if _, err := os.Stat(m.Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unscoped observation persisted state: %v", err)
			}
		})
	}
}

func TestUnknownProfilesNeverGrantAuthority(t *testing.T) {
	unknown := []string{"", defaultProfile, legacyProfile, "wan-a", "wan-", "wan-AAAAAAAAAAAA", " " + testProfileA}
	for _, profile := range unknown {
		t.Run(profile, func(t *testing.T) {
			m, _ := newScopedTestManager("")
			if _, err := m.ObserveForProfile(profile, acceptedResult(time.Now().UTC())); !errors.Is(err, ErrUnknownNetworkProfile) {
				t.Fatalf("unknown expected profile accepted: %v", err)
			}
			m.Profile = func() string { return profile }
			if _, err := m.ObserveForProfile(testProfileA, acceptedResult(time.Now().UTC())); !errors.Is(err, ErrUnknownNetworkProfile) {
				t.Fatalf("unknown current profile accepted: %v", err)
			}
			if len(m.doc.Profiles) != 0 {
				t.Fatalf("unknown profile created evidence: %+v", m.doc.Profiles)
			}
		})
	}

	m, _ := New("")
	if _, err := m.ObserveForProfile(testProfileA, acceptedResult(time.Now().UTC())); !errors.Is(err, ErrUnknownNetworkProfile) {
		t.Fatalf("absent profile provider granted authority: %v", err)
	}
}

func TestLateObservationDoesNotRebindOrChangeHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smart-route.json")
	m, _ := newScopedTestManager(path)
	now := time.Now().UTC()
	if _, err := m.ObserveForProfile(testProfileA, acceptedResult(now)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Profile = func() string { return testProfileB }
	late := acceptedResult(now)
	late[0].Status = "fail"
	decisions, err := m.ObserveForProfile(testProfileA, late)
	if !errors.Is(err, ErrNetworkProfileChanged) || len(decisions) != 0 {
		t.Fatalf("late observation accepted: decisions=%+v err=%v", decisions, err)
	}
	if got := m.Suggest("svc", "direct"); got != "direct" {
		t.Fatalf("old network armed current suggestion: %q", got)
	}
	if len(m.doc.Profiles) != 1 || m.doc.Profiles[testProfileA]["svc"].Evidence["usque"].Status != "pass" {
		t.Fatalf("late result changed historical evidence: %+v", m.doc.Profiles)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected observation changed persisted history")
	}
}

func TestObservationCannotRelabelAnotherProfilesRows(t *testing.T) {
	for _, field := range []string{"row", "structured", "both"} {
		t.Run(field, func(t *testing.T) {
			m, _ := newScopedTestManager(filepath.Join(t.TempDir(), "smart-route.json"))
			now := time.Now().UTC()
			if _, err := m.ObserveForProfile(testProfileA, acceptedResult(now)); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(m.Path)
			rows := append(acceptedResult(now), acceptedResult(now)...)
			rows[0].Status = "fail"
			rows[1].NormalizeEvidence()
			if field == "row" || field == "both" {
				rows[1].NetworkProfileID = testProfileB
			}
			if field == "structured" || field == "both" {
				rows[1].EvidenceV2.NetworkProfile = testProfileB
			}
			if got, err := m.ObserveForProfile(testProfileA, rows); !errors.Is(err, ErrNetworkProfileChanged) || got != nil {
				t.Fatalf("another profile was relabeled: %+v, %v", got, err)
			}
			after, _ := os.ReadFile(m.Path)
			if !bytes.Equal(before, after) || m.doc.Profiles[testProfileA]["svc"].Evidence["usque"].Status != "pass" {
				t.Fatal("rejected batch changed historical evidence")
			}
		})
	}
}

func TestReadOnlyProfileCallbacksRunWithoutHistoryMutex(t *testing.T) {
	m, _ := newScopedTestManager("")
	reads := 0
	m.Profile = func() string {
		if !m.mu.TryLock() {
			t.Fatal("read-only profile callback ran with the history mutex held")
		}
		m.mu.Unlock()
		reads++
		return testProfileA
	}
	_ = m.Suggest("svc", "direct")
	_ = m.Snapshot()
	if reads != 2 {
		t.Fatalf("unexpected number of profile reads: %d", reads)
	}
}

func TestNetworkChangeDuringObservationDoesNotCommit(t *testing.T) {
	m, _ := newScopedTestManager(filepath.Join(t.TempDir(), "smart-route.json"))
	now := time.Now().UTC()
	if _, err := m.ObserveForProfile(testProfileA, acceptedResult(now)); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(m.doc)
	fileBefore, _ := os.ReadFile(m.Path)
	reads := 0
	m.Profile = func() string {
		reads++
		if reads == 1 {
			return testProfileA
		}
		return testProfileB
	}
	results := acceptedResult(now)
	results[0].Status = "fail"
	decisions, err := m.ObserveForProfile(testProfileA, results)
	if !errors.Is(err, ErrNetworkProfileChanged) || len(decisions) != 0 || reads != 2 {
		t.Fatalf("changed network was committed: decisions=%+v reads=%d err=%v", decisions, reads, err)
	}
	after, _ := json.Marshal(m.doc)
	fileAfter, _ := os.ReadFile(m.Path)
	if !bytes.Equal(before, after) || !bytes.Equal(fileBefore, fileAfter) {
		t.Fatal("network changed during observation and modified history")
	}
}

func TestInvalidAndFutureProbeTimesAreNotRewrittenAsFresh(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, checked := range []string{"", "invalid", now.Add(time.Nanosecond).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339)} {
		t.Run(checked, func(t *testing.T) {
			m, _ := newScopedTestManager("")
			m.now = func() time.Time { return now }
			results := acceptedResult(now)
			results[0].CheckedAt = checked
			decisions, err := m.ObserveForProfile(testProfileA, results)
			if err != nil || len(decisions) != 0 || len(m.doc.Profiles) != 0 || m.Suggest("svc", "direct") != "direct" {
				t.Fatalf("invalid timestamp armed a route: decisions=%+v err=%v state=%+v", decisions, err, m.doc)
			}
		})
	}
	m, _ := newScopedTestManager("")
	m.now = func() time.Time { return now }
	results := acceptedResult(now)
	results[0].NormalizeEvidence()
	results[0].EvidenceV2.FinishedAt = now.Add(time.Hour)
	if decisions, err := m.ObserveForProfile(testProfileA, results); err != nil || len(decisions) != 0 || len(m.doc.Profiles) != 0 {
		t.Fatalf("future structured evidence armed a route: decisions=%+v err=%v state=%+v", decisions, err, m.doc)
	}
}

func TestOlderResultCannotReplaceNewerFailure(t *testing.T) {
	m, _ := newScopedTestManager("")
	now := time.Now().UTC()
	failure := acceptedResult(now)
	failure[0].Status = "fail"
	if _, err := m.ObserveForProfile(testProfileA, failure); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ObserveForProfile(testProfileA, acceptedResult(now.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if got := m.Suggest("svc", "direct"); got != "direct" || m.Snapshot().Services["svc"].Evidence["usque"].Status != "fail" {
		t.Fatalf("older success replaced newer failure: suggestion=%q state=%+v", got, m.Snapshot())
	}
}

func TestFreshObservationReplacesFutureHistory(t *testing.T) {
	m, _ := newScopedTestManager("")
	now := time.Now().UTC()
	m.doc.Profiles[testProfileA] = map[string]ServiceState{"svc": {SelectedRoute: "usque", Evidence: map[string]Evidence{"usque": {Route: "usque", Status: "pass", Level: evidence.Service, ConfirmedAt: now.Add(time.Hour).Format(time.RFC3339)}}}}
	if _, err := m.ObserveForProfile(testProfileA, acceptedResult(now)); err != nil {
		t.Fatal(err)
	}
	if got := m.Suggest("svc", "direct"); got != "usque" {
		t.Fatalf("future history prevented a fresh recheck: %q", got)
	}
}

func TestReloadedUnknownFutureAndExpiredHistoryNeverArms(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, profile, checked, freshUntil string
		withoutProvider                    bool
	}{
		{name: "no-provider", profile: defaultProfile, checked: now.Format(time.RFC3339), withoutProvider: true},
		{name: "unknown", profile: defaultProfile, checked: now.Format(time.RFC3339)},
		{name: "legacy-label", profile: "wan-a", checked: now.Format(time.RFC3339)},
		{name: "future", profile: testProfileA, checked: now.Add(time.Hour).Format(time.RFC3339)},
		{name: "expired-proof", profile: testProfileA, checked: now.Add(-time.Minute).Format(time.RFC3339), freshUntil: now.Format(time.RFC3339)},
		{name: "malformed-proof-expiry", profile: testProfileA, checked: now.Format(time.RFC3339), freshUntil: "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "smart-route.json")
			stored := document{Schema: schema, Profiles: map[string]map[string]ServiceState{tc.profile: {"svc": {SelectedRoute: "usque", Evidence: map[string]Evidence{"usque": {Route: "usque", Status: "pass", Level: evidence.Service, ConfirmedAt: tc.checked, FreshUntil: tc.freshUntil}}}}}}
			data, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			m, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.withoutProvider {
				m.Profile = func() string { return tc.profile }
			}
			m.now = func() time.Time { return now }
			if got := m.Suggest("svc", "direct"); got != "direct" {
				t.Fatalf("untrusted history armed a route: %q", got)
			}
			if len(m.doc.Profiles[tc.profile]) != 1 {
				t.Fatal("historical evidence was discarded")
			}
		})
	}
}
