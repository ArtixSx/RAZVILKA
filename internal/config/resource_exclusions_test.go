package config

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func exclusionStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.NetworkPolicy = networkPolicyFixture()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func ruSnapshot(revision uint64) *AcceptedRussianSnapshot {
	v := &AcceptedRussianSnapshot{CatalogID: "ru-reviewed", Revision: revision, Entries: []ResourceMatch{{Kind: "service", Value: "bank"}, {Kind: "suffix", Value: "bank.example.ru"}}}
	v.Digest = RussianSnapshotDigest(v)
	return v
}

func TestResourceExclusionsAtomicPersistenceIndependentManualAndFeed(t *testing.T) {
	s, path := exclusionStore(t)
	manual := []ResourceMatch{{Kind: "exact", Value: "ПРИМЕР.РФ"}, {Kind: "service", Value: "video"}}
	enabled := true
	first, err := s.UpdateResourceExclusionsPatch(context.Background(), s.Get(), ResourceExclusionsPatch{Manual: &manual, Accepted: ruSnapshot(1), RussianEnabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if first.NetworkPolicy.Exclusions.Revision != 1 || first.NetworkPolicy.Revision != 2 || first.Revision != 1 || !first.SafeMode || len(first.AppliedServices) != 0 || first.AppliedNetworkPolicy != nil {
		t.Fatal("edit activated traffic or wrong revisions", first)
	}
	if first.NetworkPolicy.Exclusions.Manual[0].Value != "xn--e1afmkfd.xn--p1ai" {
		t.Fatal("IDN not normalized")
	}
	first.NetworkPolicy.Exclusions.Manual[0].Value = "mutated.example"
	first.NetworkPolicy.Exclusions.RussianSnapshot.Entries[0].Value = "mutated.example"
	before := s.Get()
	loaded, err := LoadExisting(path)
	if err != nil || !reflect.DeepEqual(loaded.Get(), before) {
		t.Fatal("reload lost exclusions", err)
	}
	bytesBefore, _ := os.ReadFile(path)
	for _, bad := range []string{"empty", "digest", "entry", "replay", "catalog"} {
		t.Run(bad, func(t *testing.T) {
			feed := ruSnapshot(2)
			switch bad {
			case "empty":
				feed.Entries = nil
				feed.Digest = RussianSnapshotDigest(feed)
			case "digest":
				feed.Digest = strings.Repeat("a", 64)
			case "entry":
				feed.Entries[0] = ResourceMatch{Kind: "cidr", Value: "0.0.0.0/0"}
				feed.Digest = RussianSnapshotDigest(feed)
			case "replay":
				feed = ruSnapshot(1)
			case "catalog":
				feed.CatalogID = "different"
				feed.Digest = RussianSnapshotDigest(feed)
			}
			clear := []ResourceMatch{}
			if _, err := s.UpdateResourceExclusions(context.Background(), before, &clear, feed); err == nil {
				t.Fatal("invalid feed committed")
			}
			actual, _ := os.ReadFile(path)
			if !reflect.DeepEqual(s.Get(), before) || string(actual) != string(bytesBefore) {
				t.Fatal("rejected feed cleared manual or accepted snapshot")
			}
		})
	}
	updated, err := s.UpdateResourceExclusions(context.Background(), before, nil, ruSnapshot(2))
	if err != nil || !reflect.DeepEqual(updated.NetworkPolicy.Exclusions.Manual, before.NetworkPolicy.Exclusions.Manual) {
		t.Fatal("feed update replaced manual", err)
	}
	clear := []ResourceMatch{}
	updated, err = s.UpdateResourceExclusions(context.Background(), updated, &clear, nil)
	if err != nil || len(updated.NetworkPolicy.Exclusions.Manual) != 0 || updated.NetworkPolicy.Exclusions.RussianSnapshot.Revision != 2 {
		t.Fatal("explicit manual clear erased feed", err)
	}
	disabled := false
	updated, err = s.UpdateResourceExclusionsPatch(context.Background(), updated, ResourceExclusionsPatch{RussianEnabled: &disabled})
	if err != nil || updated.NetworkPolicy.Exclusions.RussianSnapshot.Revision != 2 {
		t.Fatal("disable erased retained feed", err)
	}
	if excluded, err := ResourceExcluded(updated.NetworkPolicy, ResourceTarget{ServiceID: "bank"}); err != nil || excluded {
		t.Fatal("disabled feed participates", excluded, err)
	}
	updated, err = s.UpdateResourceExclusionsPatch(context.Background(), updated, ResourceExclusionsPatch{RussianEnabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if excluded, err := ResourceExcluded(updated.NetworkPolicy, ResourceTarget{ServiceID: "bank"}); err != nil || !excluded {
		t.Fatal("re-enable lost retained feed", excluded, err)
	}
}

func TestResourceExclusionsCASBookendsCancellationAndStrictDecode(t *testing.T) {
	s, path := exclusionStore(t)
	before := s.Get()
	manual := []ResourceMatch{{Kind: "ip", Value: "203.0.113.1"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.UpdateResourceExclusions(ctx, before, &manual, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, s.Get()) {
		t.Fatal("cancelled edit wrote")
	}
	changed := before
	changed.Listen = ":9999"
	if _, err := s.UpdateResourceExclusions(context.Background(), changed, &manual, nil); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("same revision preimage accepted", err)
	}
	after, err := s.UpdateResourceExclusions(context.Background(), before, &manual, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateResourceExclusions(context.Background(), before, &manual, nil); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale patch accepted", err)
	}
	after.NetworkPolicy.Exclusions.Schema = 99
	raw, _ := json.Marshal(after)
	if _, _, err := InspectBytes(raw); err == nil {
		t.Fatal("unknown exclusions schema ignored")
	}
	after.NetworkPolicy.Exclusions.Schema = 1
	after.NetworkPolicy.Exclusions.Manual[0].Kind = "command"
	raw, _ = json.Marshal(after)
	if _, _, err := InspectBytes(raw); err == nil {
		t.Fatal("unknown selector ignored")
	}
	// A second writer changing bytes at the same revision is not adopted.
	actual, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(actual, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	current := s.Get()
	if _, err := s.UpdateResourceExclusions(context.Background(), current, &manual, nil); err == nil || !reflect.DeepEqual(s.Get(), current) {
		t.Fatal("external file image accepted", err)
	}
}

func TestResourceExclusionsDomainIDNAddressAndMandatoryPrecedence(t *testing.T) {
	p := networkPolicyFixture()
	entries := []ResourceMatch{{Kind: "exact", Value: "exact.example"}, {Kind: "suffix", Value: "example.com"}, {Kind: "exact", Value: "пример.рф"}, {Kind: "service", Value: "video"}, {Kind: "ip", Value: "203.0.113.7"}, {Kind: "cidr", Value: "2001:db8::/32"}}
	canonical, err := NormalizeResourceMatches(entries)
	if err != nil {
		t.Fatal(err)
	}
	p.Exclusions = &ResourceExclusions{Schema: 1, Revision: 1, Manual: canonical}
	p.Rules = []NetworkRule{{ID: "mandatory-include", Revision: 1, Kind: "suffix", Value: "example.com", Action: "bypass", Mandatory: true}}
	for _, tt := range []struct {
		target ResourceTarget
		want   bool
	}{
		{ResourceTarget{Domain: "example.com"}, true}, {ResourceTarget{Domain: "a.example.com"}, true},
		{ResourceTarget{Domain: "EXAMPLE.COM."}, true}, {ResourceTarget{Domain: "notexample.com"}, false},
		{ResourceTarget{Domain: "example.com.evil.test"}, false}, {ResourceTarget{Domain: "exact.example"}, true},
		{ResourceTarget{Domain: "sub.exact.example"}, false}, {ResourceTarget{Domain: "ПРИМЕР.РФ"}, true},
		{ResourceTarget{ServiceID: "video"}, true}, {ResourceTarget{ServiceID: "other"}, false},
		{ResourceTarget{Address: netip.MustParseAddr("203.0.113.7")}, true}, {ResourceTarget{Address: netip.MustParseAddr("203.0.113.8")}, false},
		{ResourceTarget{Address: netip.MustParseAddr("2001:db8::abcd")}, true}, {ResourceTarget{Address: netip.MustParseAddr("2001:db9::1")}, false},
		{ResourceTarget{Domain: "other.ru"}, false},
	} {
		if got, err := ResourceExcluded(p, tt.target); err != nil || got != tt.want {
			t.Errorf("%+v got=%v want=%v err=%v", tt.target, got, tt.want, err)
		}
	}
	for _, target := range []ResourceTarget{{}, {Domain: "https://example.com"}, {ServiceID: "../../evil"}, {Address: netip.MustParseAddr("::ffff:203.0.113.7")}} {
		if _, err := ResourceExcluded(p, target); err == nil {
			t.Fatal("unknown target returned eligibility", target)
		}
	}
	for _, entry := range []ResourceMatch{{Kind: "suffix", Value: "ru"}, {Kind: "cidr", Value: "203.0.113.7/24"}, {Kind: "cidr", Value: "::/0"}, {Kind: "ip", Value: "127.0.0.1"}, {Kind: "argv", Value: "--new"}} {
		if _, err := NormalizeResourceMatches([]ResourceMatch{entry}); err == nil {
			t.Fatal("invalid entry", entry)
		}
	}
	if _, err := NormalizeResourceMatches([]ResourceMatch{{Kind: "exact", Value: "пример.рф"}, {Kind: "exact", Value: "xn--e1afmkfd.xn--p1ai"}}); err == nil {
		t.Fatal("IDN alias duplicate accepted")
	}
}

func TestEffectiveExclusionDigestEmptyCloneAndLegacyScope(t *testing.T) {
	empty, err := EffectiveResourceExclusions(nil)
	if err != nil || empty.Revision != 0 || empty.PolicyRevision != 0 || len(empty.Digest) != 64 || empty.Manual == nil {
		t.Fatal("empty semantics", empty, err)
	}
	p := networkPolicyFixture()
	p.Rules = []NetworkRule{{ID: "old-negative", Revision: 1, Kind: "suffix", Value: "example.com", Action: "direct", Mandatory: true, DeviceIDs: []string{"laptop"}}, {ID: "positive", Revision: 1, Kind: "exact", Value: "a.example.com", Action: "bypass", Mandatory: true}}
	p.Russian = RussianExclusions{Enabled: true, CatalogID: "old-ru", Revision: 1, Digest: strings.Repeat("a", 64), ServiceIDs: []string{"bank"}, BroadTLDs: []string{"ru"}}
	p.Exclusions = &ResourceExclusions{Schema: 1, Revision: 1, Manual: []ResourceMatch{{Kind: "service", Value: "video"}}, RussianSnapshot: ruSnapshot(1)}
	before := CloneNetworkPolicy(p)
	v, err := EffectiveResourceExclusions(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		t    ResourceTarget
		want bool
	}{{ResourceTarget{Domain: "a.example.com", DeviceID: "laptop"}, true}, {ResourceTarget{Domain: "a.example.com", DeviceID: "phone"}, false}, {ResourceTarget{Domain: "other.ru"}, true}, {ResourceTarget{ServiceID: "bank"}, true}} {
		if got, err := v.Matches(tt.t); err != nil || got != tt.want {
			t.Fatal(tt, got, err)
		}
	}
	if _, err := v.Matches(ResourceTarget{Domain: "a.example.com"}); err == nil {
		t.Fatal("unknown device waived a matching scoped legacy negative")
	}
	v.Clients.SegmentIDs[0] = "mutated"
	v.LegacyRules[0].DeviceIDs[0] = "mutated"
	v.Russian[0].Value = "mutated.example"
	if !reflect.DeepEqual(p, before) {
		t.Fatal("effective view aliased source")
	}
	original, _ := EffectiveResourceExclusions(p)
	for _, edit := range []func(*NetworkPolicy){func(p *NetworkPolicy) { p.Rules[0].DeviceIDs[0] = "phone" }, func(p *NetworkPolicy) { p.Russian.Enabled = false; p.Russian.AutoUpdateAllowed = false }, func(p *NetworkPolicy) { p.Clients.ExcludedDeviceIDs = []string{"phone"} }, func(p *NetworkPolicy) {
		p.Exclusions.Manual = append(p.Exclusions.Manual, ResourceMatch{Kind: "exact", Value: "other.example"})
	}} {
		c := CloneNetworkPolicy(p)
		edit(c)
		changed, err := EffectiveResourceExclusions(c)
		if err != nil || changed.Digest == original.Digest {
			t.Fatal("negative/scope change did not revoke digest", err)
		}
	}
	c := CloneNetworkPolicy(p)
	slices.Reverse(c.Exclusions.RussianSnapshot.Entries)
	if RussianSnapshotDigest(c.Exclusions.RussianSnapshot) != p.Exclusions.RussianSnapshot.Digest {
		t.Fatal("canonical feed digest depends on order")
	}
}

func TestHistoricalFullConsentNeverCurrentAndPositiveReviewPreservesNegatives(t *testing.T) {
	cfg := Default()
	cfg.Revision = 5
	cfg.NetworkPolicy = allInternetPolicy()
	c := &DefaultRouteConsent{Schema: 1, InstallationID: "0123456789abcdef0123456789abcdef", Sequence: 1, ApprovalRevision: 5, ConfigRevision: 5, Policy: CloneNetworkPolicy(cfg.NetworkPolicy), Grants: []DefaultRouteGrant{consentConfigGrant()}}
	c.Digest = DefaultRouteConsentDigest(c)
	cfg.DefaultRouteConsent = c
	if ValidateDefaultRouteConsent(c) != nil || CurrentDefaultRouteConsent(cfg) {
		t.Fatal("historical full approval became current")
	}
	raw, _ := json.Marshal(cfg)
	loaded, _, err := InspectBytes(raw)
	if err != nil || CurrentDefaultRouteConsent(loaded) || ValidateListNetworkPolicy(loaded.NetworkPolicy) == nil {
		t.Fatal("legacy decode silently grants/migrates", err)
	}
	s, _ := exclusionStore(t)
	manual := []ResourceMatch{{Kind: "service", Value: "video"}}
	before, err := s.UpdateResourceExclusions(context.Background(), s.Get(), &manual, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := CloneNetworkPolicy(before.NetworkPolicy)
	p.Revision++
	p.Exclusions = nil
	if _, err := s.ApproveDefaultRouteConsent(context.Background(), before, p, []DefaultRouteGrant{consentConfigGrant()}, c.InstallationID, 1); !errors.Is(err, ErrDefaultRouteConsent) || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("positive review erased negatives", err)
	}
	p = allInternetPolicy()
	p.Revision = before.NetworkPolicy.Revision + 1
	if _, err := s.ApproveDefaultRouteConsent(context.Background(), before, p, []DefaultRouteGrant{consentConfigGrant()}, c.InstallationID, 1); err == nil {
		t.Fatal("new full approval allowed")
	}
}

func TestActualStoreExclusionObservationBookendsFullConfigAndDisk(t *testing.T) {
	s, path := exclusionStore(t)
	manual := []ResourceMatch{{Kind: "service", Value: "video"}}
	expected, err := s.UpdateResourceExclusions(context.Background(), s.Get(), &manual, nil)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := s.WithResourceExclusionObservation(context.Background(), expected, func(set EffectiveExclusionSet) error {
		called = true
		if excluded, err := set.Matches(ResourceTarget{ServiceID: "video"}); err != nil || !excluded {
			t.Fatal("actual stored negatives absent", excluded, err)
		}
		set.Manual[0].Value = "mutated"
		return nil
	}); err != nil || !called || !reflect.DeepEqual(s.Get(), expected) {
		t.Fatal("observation alias/bookend", err)
	}
	wrong := cloneConfig(expected)
	wrong.Listen = ":9999"
	called = false
	if err := s.WithResourceExclusionObservation(context.Background(), wrong, func(EffectiveExclusionSet) error { called = true; return nil }); !errors.Is(err, ErrRevisionChanged) || called {
		t.Fatal("same revision DTO granted callback", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.WithResourceExclusionObservation(ctx, expected, func(EffectiveExclusionSet) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled closing observation succeeded", err)
	}
	if err := s.WithResourceExclusionObservation(context.Background(), expected, func(EffectiveExclusionSet) error {
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(path, append(bytes, '\n'), 0600)
	}); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("changed closing file accepted", err)
	}
}

func TestInactiveExclusionsPersistenceStrictSingleSlotAndFirstExplicitScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	manual := []ResourceMatch{{Kind: "service", Value: "video"}}
	inactive, err := s.UpdateResourceExclusions(context.Background(), before, &manual, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inactive.NetworkPolicy != nil || inactive.DefaultRouteConsent != nil || inactive.InactiveResourceExclusions.Revision != 1 || inactive.Revision != before.Revision+1 || inactive.SafeMode != before.SafeMode {
		t.Fatal("inactive storage inferred scope/grant", inactive)
	}
	loaded, err := LoadExisting(path)
	if err != nil || !reflect.DeepEqual(loaded.Get(), inactive) {
		t.Fatal("reload lost inactive record", err)
	}
	view := loaded.Get()
	view.InactiveResourceExclusions.Manual[0].Value = "changed"
	if !reflect.DeepEqual(loaded.Get(), inactive) {
		t.Fatal("inactive clone alias")
	}
	if excluded, err := ConfigResourceExcluded(inactive, ResourceTarget{ServiceID: "video"}); err != nil || !excluded {
		t.Fatal("config-aware helper omitted inactive negatives", excluded, err)
	}
	if err := s.WithResourceExclusionObservation(context.Background(), inactive, func(set EffectiveExclusionSet) error {
		if set.PolicyRevision != 0 || set.Revision != 1 || set.Clients.Mode != "" {
			t.Fatal("inactive observer invented scope", set)
		}
		excluded, err := set.Matches(ResourceTarget{ServiceID: "video"})
		if !excluded || err != nil {
			t.Fatal(excluded, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := networkPolicyFixture()
	dual := cloneConfig(inactive)
	dual.NetworkPolicy = p
	raw, _ := json.Marshal(dual)
	if _, _, err := InspectBytes(raw); err == nil {
		t.Fatal("dualactive/inactive state accepted")
	}
	future := cloneConfig(inactive)
	future.InactiveResourceExclusions.Schema = 99
	raw, _ = json.Marshal(future)
	if _, _, err := InspectBytes(raw); err == nil {
		t.Fatal("future inactive schema discarded")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	clear := []ResourceMatch{}
	if _, err := s.UpdateResourceExclusions(cancelled, inactive, &clear, nil); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(s.Get(), inactive) {
		t.Fatal("cancelled inactive clear", err)
	}
	if _, err := s.UpdateResourceExclusions(context.Background(), before, &clear, nil); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale inactive CAS", err)
	}
	p.Exclusions = &ResourceExclusions{Schema: 1, Revision: 1, Manual: []ResourceMatch{}}
	if _, err := s.ApproveDefaultRouteConsent(context.Background(), inactive, p, []DefaultRouteGrant{consentConfigGrant()}, "0123456789abcdef0123456789abcdef", 1); err == nil || !reflect.DeepEqual(s.Get(), inactive) {
		t.Fatal("newscope cleared inactive record", err)
	}
	p.Exclusions = nil
	if _, err := s.ApproveDefaultRouteConsent(context.Background(), inactive, p, []DefaultRouteGrant{consentConfigGrant()}, "0123456789abcdef0123456789abcdef", 1); err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	if after.InactiveResourceExclusions != nil || !reflect.DeepEqual(after.NetworkPolicy.Exclusions, inactive.InactiveResourceExclusions) || after.NetworkPolicy.Revision != 1 || after.Revision != inactive.Revision+1 || after.AppliedNetworkPolicy != nil {
		t.Fatal("nonatomic/lossy first review", after)
	}
}
