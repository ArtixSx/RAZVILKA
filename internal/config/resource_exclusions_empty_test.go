package config

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResourceExclusionStateEqualTreatsOnlyEmptyNegativeArraysAsEquivalent(t *testing.T) {
	for _, field := range []string{"cold-russian", "manual", "snapshot-entries", "direct-rule-devices"} {
		t.Run(field, func(t *testing.T) {
			a := networkPolicyFixture()
			switch field {
			case "manual":
				a.Exclusions = &ResourceExclusions{Schema: 1, Revision: 4}
			case "snapshot-entries":
				// An empty feed remains invalid. This comparison is not its
				// validator; the separate approval test below keeps it refused.
				a.Exclusions = &ResourceExclusions{Schema: 1, Revision: 4, RussianSnapshot: &AcceptedRussianSnapshot{CatalogID: "ru-retained", Revision: 3, Digest: strings.Repeat("a", 64)}}
			case "direct-rule-devices":
				a.Rules = []NetworkRule{{ID: "negative", Revision: 1, Kind: "service", Value: "video", Action: "direct"}}
			}
			b := CloneNetworkPolicy(a)
			b.Russian.ServiceIDs, b.Russian.BroadTLDs = []string{}, []string{}
			if b.Exclusions != nil {
				b.Exclusions.Manual = []ResourceMatch{}
				if b.Exclusions.RussianSnapshot != nil {
					b.Exclusions.RussianSnapshot.Entries = []ResourceMatch{}
				}
			}
			if len(b.Rules) != 0 {
				b.Rules[0].DeviceIDs = []string{}
			}
			beforeA, beforeB := CloneNetworkPolicy(a), CloneNetworkPolicy(b)
			if !ResourceExclusionStateEqual(a, b) || !ResourceExclusionStateEqual(b, a) || field == "cold-russian" && !ResourceExclusionStateEqual(nil, b) {
				t.Fatal("equivalent empty negative JSON shape was refused")
			}
			if !reflect.DeepEqual(a, beforeA) || !reflect.DeepEqual(b, beforeB) {
				t.Fatal("comparison rewrote the caller's policy/negative arrays")
			}
		})
	}
}

func TestResourceExclusionStateEqualKeepsDisabledRetainedFieldsAndActualChangesExact(t *testing.T) {
	p := networkPolicyFixture()
	p.Russian = RussianExclusions{Enabled: false, CatalogID: "ru-retained", Revision: 3, Digest: strings.Repeat("a", 64), ServiceIDs: []string{"bank", "video"}, BroadTLDs: []string{"ru", "su"}}
	snapshot := &AcceptedRussianSnapshot{CatalogID: "ru-retained", Revision: 3, Entries: []ResourceMatch{{Kind: "service", Value: "bank"}}}
	snapshot.Digest = RussianSnapshotDigest(snapshot)
	p.Exclusions = &ResourceExclusions{Schema: 1, Revision: 4, Manual: []ResourceMatch{{Kind: "exact", Value: "manual.example"}}, RussianSnapshot: snapshot}
	p.Rules = []NetworkRule{{ID: "negative", Revision: 2, Kind: "service", Value: "video", Action: "direct", DeviceIDs: []string{"device-a", "device-b"}}}
	for _, test := range []struct {
		name   string
		change func(*NetworkPolicy)
	}{
		{"enabled", func(q *NetworkPolicy) { q.Russian.Enabled = true }},
		{"auto-update", func(q *NetworkPolicy) { q.Russian.AutoUpdateAllowed = true }},
		{"catalog", func(q *NetworkPolicy) { q.Russian.CatalogID = "other" }},
		{"revision", func(q *NetworkPolicy) { q.Russian.Revision++ }},
		{"digest", func(q *NetworkPolicy) { q.Russian.Digest = strings.Repeat("b", 64) }},
		{"services-clear", func(q *NetworkPolicy) { q.Russian.ServiceIDs = []string{} }},
		{"services-order", func(q *NetworkPolicy) {
			q.Russian.ServiceIDs[0], q.Russian.ServiceIDs[1] = q.Russian.ServiceIDs[1], q.Russian.ServiceIDs[0]
		}},
		{"tlds-clear", func(q *NetworkPolicy) { q.Russian.BroadTLDs = nil }},
		{"document-clear", func(q *NetworkPolicy) { q.Exclusions = nil }},
		{"document-schema", func(q *NetworkPolicy) { q.Exclusions.Schema++ }},
		{"document-revision", func(q *NetworkPolicy) { q.Exclusions.Revision++ }},
		{"manual-clear", func(q *NetworkPolicy) { q.Exclusions.Manual = []ResourceMatch{} }},
		{"manual-change", func(q *NetworkPolicy) { q.Exclusions.Manual[0].Value = "other.example" }},
		{"snapshot-clear", func(q *NetworkPolicy) { q.Exclusions.RussianSnapshot = nil }},
		{"snapshot-catalog", func(q *NetworkPolicy) { q.Exclusions.RussianSnapshot.CatalogID = "other" }},
		{"snapshot-revision", func(q *NetworkPolicy) { q.Exclusions.RussianSnapshot.Revision++ }},
		{"snapshot-digest", func(q *NetworkPolicy) { q.Exclusions.RussianSnapshot.Digest = strings.Repeat("b", 64) }},
		{"snapshot-empty", func(q *NetworkPolicy) { q.Exclusions.RussianSnapshot.Entries = []ResourceMatch{} }},
		{"snapshot-change", func(q *NetworkPolicy) { q.Exclusions.RussianSnapshot.Entries[0].Value = "other" }},
		{"rule-clear", func(q *NetworkPolicy) { q.Rules = nil }},
		{"rule-id", func(q *NetworkPolicy) { q.Rules[0].ID = "other" }},
		{"rule-revision", func(q *NetworkPolicy) { q.Rules[0].Revision++ }},
		{"rule-kind", func(q *NetworkPolicy) { q.Rules[0].Kind = "suffix" }},
		{"rule-value", func(q *NetworkPolicy) { q.Rules[0].Value = "other" }},
		{"rule-action", func(q *NetworkPolicy) { q.Rules[0].Action = "bypass" }},
		{"rule-mandatory", func(q *NetworkPolicy) { q.Rules[0].Mandatory = true }},
		{"rule-devices-clear", func(q *NetworkPolicy) { q.Rules[0].DeviceIDs = []string{} }},
		{"rule-devices-order", func(q *NetworkPolicy) {
			q.Rules[0].DeviceIDs[0], q.Rules[0].DeviceIDs[1] = q.Rules[0].DeviceIDs[1], q.Rules[0].DeviceIDs[0]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := CloneNetworkPolicy(p)
			test.change(q)
			if ResourceExclusionStateEqual(p, q) || ResourceExclusionStateEqual(q, p) {
				t.Fatal("ordinary approval waived an actual retained negative change")
			}
		})
	}
	if ResourceExclusionStateEqual(nil, &NetworkPolicy{Exclusions: &ResourceExclusions{Schema: 1, Revision: 1, Manual: []ResourceMatch{}}}) || ResourceExclusionStateEqual(&NetworkPolicy{Exclusions: &ResourceExclusions{Schema: 1, Revision: 1}}, &NetworkPolicy{Exclusions: &ResourceExclusions{Schema: 1, Revision: 1, RussianSnapshot: &AcceptedRussianSnapshot{}}}) {
		t.Fatal("empty arrays erased the presence of an actual document/snapshot")
	}
}

func TestEmptyNegativeFirstApprovalPreservesStrictStoreCASAndInvalidFeedRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	p := networkPolicyFixture()
	p.Schema = 2
	p.Russian.ServiceIDs, p.Russian.BroadTLDs = []string{}, []string{}
	grants := []DefaultRouteGrant{consentConfigGrant()}
	approve := func(ctx context.Context, expected Config, policy *NetworkPolicy) error {
		_, err := s.ApproveDefaultRouteConsent(ctx, expected, policy, grants, "0123456789abcdef0123456789abcdef", 1)
		return err
	}
	forged := s.Get()
	forged.SafeMode = !forged.SafeMode
	if err := approve(context.Background(), forged, p); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("equivalent empties waived full same-revision Store equality", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := approve(canceled, before, p); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("equivalent empties waived cancellation", err)
	}
	if err := approve(context.Background(), before, p); err != nil {
		t.Fatal("exact cold Store approval rejected empty negatives", err)
	}
	after := s.Get()
	if !CurrentDefaultRouteConsent(after) || after.Revision != before.Revision+1 || !reflect.DeepEqual(after.DefaultRouteConsent.Grants, grants) || after.NetworkPolicy.Russian.ServiceIDs == nil || after.NetworkPolicy.Russian.BroadTLDs == nil {
		t.Fatal("comparison normalized persisted JSON or changed exact grants")
	}
	loaded, err := LoadExisting(path)
	if err != nil || !reflect.DeepEqual(loaded.Get(), after) {
		t.Fatal("saved exact approved image changed on reload", err)
	}
	if err := approve(context.Background(), before, p); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), after) {
		t.Fatal("equivalent empties waived stale CAS", err)
	}
	invalid := CloneNetworkPolicy(after.NetworkPolicy)
	invalid.Revision++
	invalid.Exclusions = &ResourceExclusions{Schema: 1, Revision: 1, RussianSnapshot: &AcceptedRussianSnapshot{CatalogID: "ru-empty", Revision: 1, Entries: []ResourceMatch{}}}
	invalid.Exclusions.RussianSnapshot.Digest = RussianSnapshotDigest(invalid.Exclusions.RussianSnapshot)
	if ValidateListNetworkPolicy(invalid) == nil || approve(context.Background(), after, invalid) == nil || !reflect.DeepEqual(s.Get(), after) {
		t.Fatal("empty-set equality made an invalid accepted feed approvable")
	}
	// Explicitly assert only the comparison changed: caller JSON is untouched.
	raw, err := json.Marshal(p)
	if err != nil || !strings.Contains(string(raw), `"service_ids":[]`) || !strings.Contains(string(raw), `"broad_tlds":[]`) {
		t.Fatal("comparison rewrote caller representation", err)
	}
}
