package testlab

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

const profileA = "wan-aaaaaaaaaaaa"
const profileB = "wan-bbbbbbbbbbbb"

func networkTestCatalog() catalog.Catalog {
	return catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video", ProbeURL: "https://example.com/"}}}
}

func TestUnrecordedProbeCannotPublishBeforeNetworkGuard(t *testing.T) {
	runner := NewRunner()
	current := profileA
	runner.Profile = func() string { return current }
	cat := networkTestCatalog()
	results := runner.ProbeRoutesUnrecorded(context.Background(), cat, nil, []string{"direct"}, fakeRouteProber{})
	if len(results) != 1 || results[0].AssuranceLevel() != evidence.Service {
		t.Fatalf("probe did not return its unpublished observation: %+v", results)
	}
	if got := runner.Snapshot(cat).Current; len(got) != 0 {
		t.Fatalf("unrecorded probe leaked into history: %+v", got)
	}
	current = profileB
	if got, err := runner.RecordRoutesForProfile(profileA, results); !errors.Is(err, ErrNetworkProfileChanged) || got != nil {
		t.Fatalf("late batch was accepted: %+v, %v", got, err)
	}
	if got := runner.Snapshot(cat).Current; len(got) != 0 {
		t.Fatalf("rejected batch leaked into history: %+v", got)
	}
}

func TestScopedRecordKeepsProfileAndDoesNotShareHistory(t *testing.T) {
	runner := NewRunner()
	runner.Profile = func() string { return profileA }
	cat := networkTestCatalog()
	results := runner.ProbeRoutesUnrecorded(context.Background(), cat, nil, []string{"direct"}, fakeRouteProber{})
	bound, err := runner.RecordRoutesForProfile(profileA, results)
	if err != nil {
		t.Fatal(err)
	}
	if bound[0].NetworkProfileID != profileA || bound[0].EvidenceV2.NetworkProfile != profileA || bound[0].AssuranceLevel() != evidence.Service {
		t.Fatalf("missing scoped service evidence: %+v", bound[0])
	}
	if results[0].NetworkProfileID != "" || results[0].EvidenceV2.NetworkProfile != "" {
		t.Fatal("publication mutated the original unscoped observation")
	}
	bound[0].EvidenceV2.NetworkProfile = profileB
	bound[0].NetworkProfileID = profileB
	first := runner.Snapshot(cat)
	if first.Current[0].Status != "pass" || first.Current[0].NetworkProfileID != profileA || first.Current[0].EvidenceV2.NetworkProfile != profileA {
		t.Fatalf("returned batch aliases history: %+v", first.Current[0])
	}
	first.Current[0].EvidenceV2.RouteProofError = "mutated-by-reader"
	if got := runner.Snapshot(cat).Current[0]; got.AssuranceLevel() != evidence.Service {
		t.Fatalf("snapshot aliases history: %+v", got)
	}
}

func TestScopedRecordRejectsUnknownAndConflictingProfiles(t *testing.T) {
	tests := []struct {
		name              string
		expected          string
		current           string
		rowProfile        string
		structuredProfile string
		noCallback        bool
		want              error
	}{
		{name: "unknown expected", expected: "unknown", current: profileA, want: ErrUnknownNetworkProfile},
		{name: "invalid expected", expected: "wan-AAAAAAAAAAAA", current: profileA, want: ErrUnknownNetworkProfile},
		{name: "unknown current", expected: profileA, current: "unknown", want: ErrUnknownNetworkProfile},
		{name: "missing callback", expected: profileA, noCallback: true, want: ErrUnknownNetworkProfile},
		{name: "new epoch", expected: profileA, current: profileB, want: ErrNetworkProfileChanged},
		{name: "row from another epoch", expected: profileA, current: profileA, rowProfile: profileB, want: ErrResultNetworkProfileMismatch},
		{name: "structured evidence from another epoch", expected: profileA, current: profileA, structuredProfile: profileB, want: ErrResultNetworkProfileMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := NewRunner()
			if !tc.noCallback {
				runner.Profile = func() string { return tc.current }
			}
			result := fakeRouteProber{}.Probe(context.Background(), networkTestCatalog().Services[0], "direct")
			result.NormalizeEvidence()
			result.NetworkProfileID = tc.rowProfile
			result.EvidenceV2.NetworkProfile = tc.structuredProfile
			if got, err := runner.RecordRoutesForProfile(tc.expected, []Result{result}); !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("got %+v, %v; want %v", got, err, tc.want)
			}
			if len(runner.latest) != 0 {
				t.Fatal("rejected record mutated history")
			}
		})
	}
}

func TestSnapshotRevokesOldAndUnknownProfilesWithoutErasingHistory(t *testing.T) {
	for _, current := range []string{"unknown", "", "default", "wan-AAAAAAAAAAAA", profileB} {
		t.Run(current, func(t *testing.T) {
			runner := NewRunner()
			profile := profileA
			runner.Profile = func() string { return profile }
			cat := networkTestCatalog()
			results := runner.ProbeRoutesUnrecorded(context.Background(), cat, nil, []string{"direct"}, fakeRouteProber{})
			if _, err := runner.RecordRoutesForProfile(profileA, results); err != nil {
				t.Fatal(err)
			}
			profile = current
			snapshot := runner.Snapshot(cat)
			assertNoRouteAuthority(t, snapshot.Current[0])
			for _, cell := range snapshot.Matrix {
				if cell.Route == "direct" && cell.Last != nil {
					assertNoRouteAuthority(t, *cell.Last)
				}
			}
			if snapshot.Current[0].NetworkProfileID != profileA {
				t.Fatal("history lost its original profile")
			}
			if original := runner.latest[resultKey(results[0])]; original.Status != "pass" || original.EvidenceV2.RouteProofError != "" {
				t.Fatalf("snapshot rewrote stored observation: %+v", original)
			}
		})
	}
}

func TestProductionSnapshotRevokesLegacyUnscopedHistory(t *testing.T) {
	runner := NewRunner()
	cat := networkTestCatalog()
	runner.ProbeRoutes(context.Background(), cat, nil, []string{"direct"}, fakeRouteProber{})
	if got := runner.Snapshot(cat).Current[0]; got.AssuranceLevel() != evidence.Service {
		t.Fatal("legacy nil-profile behavior changed")
	}
	runner.Profile = func() string { return profileA }
	assertNoRouteAuthority(t, runner.Snapshot(cat).Current[0])
}

func TestSnapshotCannotAggregateScenariosFromDifferentEpochs(t *testing.T) {
	runner := NewRunner()
	current := profileA
	runner.Profile = func() string { return current }
	rows := networkScenarioRows(profileA, profileB)
	if _, err := runner.RecordRoutesForProfile(current, rows[:1]); err != nil {
		t.Fatal(err)
	}
	current = profileB
	if _, err := runner.RecordRoutesForProfile(current, rows[1:]); err != nil {
		t.Fatal(err)
	}
	snapshot := runner.Snapshot(networkTestCatalog())
	if len(snapshot.Current) != 2 {
		t.Fatalf("historical scenarios were lost: %+v", snapshot.Current)
	}
	assertNoRouteAuthority(t, AggregateScenarios(snapshot.Current)[0])
	for _, cell := range snapshot.Matrix {
		if cell.Route == "direct" && cell.Last != nil {
			assertNoRouteAuthority(t, *cell.Last)
		}
	}
}

func TestAggregateCannotCombineEpochsOrEraseRevokedProof(t *testing.T) {
	for _, secondProfile := range []string{profileB, ""} {
		t.Run("mixed-"+secondProfile, func(t *testing.T) {
			rows := networkScenarioRows(profileA, secondProfile)
			aggregate := AggregateScenarios(rows)[0]
			assertNoRouteAuthority(t, aggregate)
			assertNoRouteAuthority(t, AggregateScenarios([]Result{aggregate})[0])
		})
	}
	rows := networkScenarioRows(profileA, profileA)
	rows[1].RouteProofError = "network-profile-changed"
	assertNoRouteAuthority(t, AggregateScenarios(rows)[0])
	rows = networkScenarioRows(profileA, profileA)
	got := AggregateScenarios(rows)[0]
	if got.NetworkProfileID != profileA || got.EvidenceV2.NetworkProfile != profileA || got.AssuranceLevel() != evidence.Service {
		t.Fatalf("coherent scenarios lost valid evidence: %+v", got)
	}
}

func TestNormalizeRejectsContradictoryProfileFields(t *testing.T) {
	rows := networkScenarioRows(profileA, profileA)
	rows[0].EvidenceV2.NetworkProfile = profileB
	assertNoRouteAuthority(t, rows[0])
}

func networkScenarioRows(first, second string) []Result {
	rows := []Result{
		{ServiceID: "video", Route: "direct", ScenarioID: "landing", ScenarioNeeded: true, Status: "pass", HTTPStatus: 204, RouteConfirmed: true, NetworkProfileID: first, CheckedAt: time.Now().UTC().Format(time.RFC3339)},
		{ServiceID: "video", Route: "direct", ScenarioID: "playback", ScenarioNeeded: true, Status: "pass", HTTPStatus: 204, RouteConfirmed: true, NetworkProfileID: second, CheckedAt: time.Now().UTC().Format(time.RFC3339)},
	}
	for i := range rows {
		rows[i].NormalizeEvidence()
	}
	return rows
}

func assertNoRouteAuthority(t *testing.T, result Result) {
	t.Helper()
	result.NormalizeEvidence()
	result.NormalizeEvidence()
	if result.Status == "pass" || result.Verdict == evidence.VerdictPass || result.RouteConfirmed || result.AssuranceLevel().AtLeast(evidence.Route) || result.EvidenceV2.RoutePathID != "" || result.RouteProofError == "" {
		t.Fatalf("invalid network observation retained authority: %+v", result)
	}
}
