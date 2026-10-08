package autonomy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func listPolicyFixture(t *testing.T) (*config.NetworkPolicy, ScopeObservation, TrafficQuestion) {
	t.Helper()
	p, o, q, _ := scopeFixture()
	p.Schema = 2
	p.Traffic = config.TrafficSelection{Mode: "selected_services", Unavailable: "block"}
	q.Domain, q.ServiceID, q.ServiceSelected = "unknown-new-site.example", "", false
	q.DefaultCoverage = "supported"
	return p, o, q
}

func decideAt(t *testing.T, p *config.NetworkPolicy, o ScopeObservation, q TrafficQuestion) NetworkDecision {
	t.Helper()
	_, _, _, now := scopeFixture()
	return DecideNetworkPolicy(p, o, q, now)
}

func TestListPolicyUnknownSiteAndDirectIPRemainBaseline(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	literal := TrafficQuestion{Client: q.Client, Address: netip.MustParseAddr("203.0.113.9"), DefaultCoverage: "supported"}
	for _, question := range []TrafficQuestion{q, literal} {
		d := decideAt(t, p, o, question)
		if d.Action != "base" || d.Reason != "UNSELECTED_DESTINATION" || d.Target != "" {
			t.Fatalf("unmatched destination acquired an outbound: %+v", d)
		}
	}
}

func TestListPolicyServiceScopeMissAndResourceExclusion(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	q.Domain, q.ServiceID, q.ServiceSelected = "discord.com", "discord", true
	q.ServiceSources = []string{"192.168.1.41/32"}
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "SERVICE_SCOPE_MISMATCH" || d.Target != "" {
		t.Fatal(d)
	}
	q.ServiceSources = []string{"192.168.1.40/32"}
	if d := decideAt(t, p, o, q); d.Action != "bypass" || d.Reason != "SERVICE_OVERRIDE" || d.Target != "service" {
		t.Fatal(d)
	}
	p.Russian = config.RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 1, Digest: strings.Repeat("b", 64), ServiceIDs: []string{"discord"}}
	q.ServiceSources = []string{"192.168.1.41/32"}
	q.ExplicitBypass = true
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RU_CATALOG_DIRECT" {
		t.Fatalf("positive scope miss skipped the resource exclusion: %+v", d)
	}
}

func TestListPolicyRussianExclusionPrecedesPinnedPositive(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	p.Russian = config.RussianExclusions{Enabled: true, CatalogID: "ru-curated", Revision: 1, Digest: strings.Repeat("c", 64), ServiceIDs: []string{"bank"}}
	q.Domain, q.ServiceID = "bank.example", "bank"
	p.Rules = []config.NetworkRule{{ID: "pin", Revision: 1, Kind: "exact", Value: q.Domain, Action: "bypass", Mandatory: true}}
	for _, selected := range []bool{false, true} {
		q.ServiceSelected, q.ExplicitBypass = selected, true
		if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RU_CATALOG_DIRECT" || d.Target != "" {
			t.Fatalf("selected=%v bypassed exclusion: %+v", selected, d)
		}
	}
	p.Rules = nil
	q.ServiceID, q.ServiceSelected, q.ExplicitBypass = "chatgpt", false, false
	if d := decideAt(t, p, o, q); d.Target != "" || d.Action != "base" {
		t.Fatalf("removed entry acquired an outbound: %+v", d)
	}
}

func TestListPolicyUnmatchedCoverageNeverCreatesCapture(t *testing.T) {
	for _, unavailable := range []string{"retain", "base", "block"} {
		for _, coverage := range []string{"supported", "unsupported", "unknown", ""} {
			p, o, q := listPolicyFixture(t)
			p.Traffic.Unavailable, q.DefaultCoverage = unavailable, coverage
			if d := decideAt(t, p, o, q); d.Action != "base" || d.Target != "" {
				t.Fatal(unavailable, coverage, d)
			}
		}
	}
	// Matched path coverage remains the actual adapter's separate guard.
	p, o, q := listPolicyFixture(t)
	q.DefaultCoverage = "unsupported"
	q.ServiceID, q.ServiceSelected = "youtube", true
	if d := decideAt(t, p, o, q); d.Action != "bypass" || d.Target != "service" {
		t.Fatal(d)
	}
}

func TestListPolicyExclusionsAndMissingPositivePath(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	q.Client.MAC, q.Domain, q.ExplicitBypass = o.Devices[0].MAC, "bad/name", true
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "DEVICE_EXCLUDED" || d.Target != "" {
		t.Fatal(d)
	}
	p, o, q = listPolicyFixture(t)
	p.Rules = []config.NetworkRule{{ID: "keep-direct", Revision: 1, Kind: "exact", Value: q.Domain, Action: "direct", Mandatory: true}}
	q.ServiceSources, q.ServiceSelected = []string{"not-a-prefix"}, true
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "MANUAL_DIRECT" {
		t.Fatalf("negative resource depended on positive scope: %+v", d)
	}
	p, o, q = listPolicyFixture(t)
	p.Rules = []config.NetworkRule{{ID: "force", Revision: 1, Kind: "exact", Value: q.Domain, Action: "bypass", Mandatory: true}}
	if d := decideAt(t, p, o, q); d.Action != "unavailable" || d.Reason != "LIST_ROUTE_UNAVAILABLE" || d.RuleID != "force" || d.Target != "" {
		t.Fatalf("standalone positive invented a resolved path: %+v", d)
	}
}

func TestListPolicyHistoricalAllExceptDoesNotGrantNewDecision(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	p.Traffic = config.TrafficSelection{Mode: "all_except", AllExceptAllowed: true, DefaultRoute: "wireguard", Unavailable: "block"}
	if config.ValidateNetworkPolicy(p) != nil {
		t.Fatal("historical intent is not decodable")
	}
	for _, selected := range []bool{false, true} {
		q.ServiceID, q.ServiceSelected = "listed", selected
		if d := decideAt(t, p, o, q); d.Action != "unavailable" || d.Reason != "LIST_MODE_REQUIRED" || d.Target != "" {
			t.Fatal(d)
		}
	}
}

func TestListPolicyTypedManualNegativesPrecedePinnedPositive(t *testing.T) {
	for _, match := range []config.ResourceMatch{
		{Kind: "service", Value: "bank"},
		{Kind: "exact", Value: "bank.example.com"},
		{Kind: "suffix", Value: "example.com"},
		{Kind: "ip", Value: "203.0.113.9"},
		{Kind: "cidr", Value: "203.0.113.0/24"},
	} {
		t.Run(match.Kind, func(t *testing.T) {
			p, o, q := listPolicyFixture(t)
			q.ServiceID, q.ServiceSelected, q.ExplicitBypass = "bank", true, true
			q.Domain, q.Address = "bank.example.com", netip.MustParseAddr("203.0.113.9")
			q.ServiceSources = []string{"invalid-positive-source"}
			p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 3, Manual: []config.ResourceMatch{match}}
			p.Rules = []config.NetworkRule{{ID: "pin", Revision: 1, Kind: "service", Value: "bank", Action: "bypass", Mandatory: true}}
			if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RESOURCE_EXCLUDED" || d.Target != "" || d.ExclusionRevision != 3 || len(d.ExclusionDigest) != 64 {
				t.Fatal("typed negative lost to pin or positive scope", d)
			}
		})
	}
}

func TestListPolicyTypedRussianSnapshotAndManualAreIndependent(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	q.ServiceID, q.ServiceSelected, q.ExplicitBypass = "bank", true, true
	snapshot := &config.AcceptedRussianSnapshot{CatalogID: "ru-source", Revision: 1, Entries: []config.ResourceMatch{{Kind: "service", Value: "bank"}}}
	snapshot.Digest = config.RussianSnapshotDigest(snapshot)
	p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 2, Manual: []config.ResourceMatch{{Kind: "exact", Value: "manual.example.com"}}, RussianSnapshot: snapshot}
	p.Russian.Enabled = true
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RESOURCE_EXCLUDED" {
		t.Fatal("accepted RU lost to explicit positive", d)
	}
	p.Russian.Enabled = false
	q.Domain = "manual.example.com"
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RESOURCE_EXCLUDED" {
		t.Fatal("disabling RU erased manual negative", d)
	}
}

func TestListPolicyScopedResourceNegativeRequiresActualDevice(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	q.Domain, q.ServiceID, q.ServiceSelected = "service.example.com", "service", true
	p.Rules = []config.NetworkRule{{ID: "phone-only", Revision: 1, Kind: "exact", Value: q.Domain, Action: "direct", Mandatory: true, DeviceIDs: []string{"phone"}}}
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "MANUAL_DIRECT" || d.DeviceID != "phone" {
		t.Fatal(d)
	}
	q.Client.MAC = "02:00:00:00:00:99"
	if d := decideAt(t, p, o, q); d.Action != "unavailable" || d.Reason != "RESOURCE_IDENTITY_UNAVAILABLE" {
		t.Fatal("unknown device waived a scoped resource negative", d)
	}
}

func TestListPolicyTypedSuffixBoundaryAndIDN(t *testing.T) {
	p, o, q := listPolicyFixture(t)
	q.ServiceID, q.ServiceSelected = "selected", true
	p.Exclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "suffix", Value: "example.com"}}}
	for name, action := range map[string]string{"example.com": "base", "child.example.com": "base", "notexample.com": "bypass", "example.com.evil.test": "bypass"} {
		q.Domain = name
		if d := decideAt(t, p, o, q); d.Action != action {
			t.Fatal("suffix label boundary changed", name, d)
		}
	}
	canonical, err := config.PolicyDomain("пример.рф")
	if err != nil {
		t.Fatal(err)
	}
	p.Exclusions.Manual = []config.ResourceMatch{{Kind: "exact", Value: canonical}}
	q.Domain = "пример.рф"
	if d := decideAt(t, p, o, q); d.Action != "base" || d.Reason != "RESOURCE_EXCLUDED" {
		t.Fatal("IDN alias waived exact negative", d)
	}
}
