package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func consentConfigGrant() DefaultRouteGrant {
	return DefaultRouteGrant{Resolved: "usque", ProviderClass: "cloudflare", ProviderID: "usque"}
}

func TestDefaultConsentStoreExactCASCloneSanctionedCommitAndUnrelatedRevocation(t *testing.T) {
	s, path := networkCommitFixture(t)
	before := s.Get()
	policy := CloneNetworkPolicy(before.NetworkPolicy)
	policy.Revision++
	policy.Traffic = TrafficSelection{Mode: "selected_services", Unavailable: "retain"}
	if CurrentDefaultRouteConsent(before) {
		t.Fatal("legacy all_except inferred grant")
	}
	approved, err := s.ApproveDefaultRouteConsent(context.Background(), before, policy, []DefaultRouteGrant{consentConfigGrant()}, "0123456789abcdef0123456789abcdef", 1)
	if err != nil {
		t.Fatal(err)
	}
	current := s.Get()
	if !CurrentDefaultRouteConsent(current) || current.Revision != before.Revision+1 || !reflect.DeepEqual(current.AppliedNetworkPolicy, before.AppliedNetworkPolicy) {
		t.Fatal("approval applied runtime or did not bind revision")
	}
	approved.Policy.Clients.SegmentIDs[0] = "different"
	view := s.Get()
	view.DefaultRouteConsent.Grants[0].ProviderID = "different"
	if !CurrentDefaultRouteConsent(s.Get()) {
		t.Fatal("detached approval/config mutated Store")
	}
	if _, err := s.ApproveDefaultRouteConsent(context.Background(), before, policy, []DefaultRouteGrant{consentConfigGrant()}, "0123456789abcdef0123456789abcdef", 1); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale CAS", err)
	}
	digest := current.DefaultRouteConsent.Digest
	applied, services := networkCommitCandidate(current)
	applied = CloneNetworkPolicy(current.NetworkPolicy)
	undo, err := s.CommitNetworkPolicyWithRollback(current, applied, services)
	if err != nil {
		t.Fatal(err)
	}
	committed := s.Get()
	if !CurrentDefaultRouteConsent(committed) || committed.DefaultRouteConsent.Digest != digest || committed.DefaultRouteConsent.ApprovalRevision != current.Revision {
		t.Fatal("sanctioned commit renewed or dropped exact approval")
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Get(), current) {
		t.Fatal("undo approval postimage differs")
	}
	if err := s.UpdateService("extra", ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if CurrentDefaultRouteConsent(s.Get()) {
		t.Fatal("unrelated revision retained permission")
	}
	// Stale explicit intent is retained visibly, while strict loading refuses
	// malformed declared approval instead of silently dropping it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, _, err := InspectBytes(raw)
	if err != nil || CurrentDefaultRouteConsent(loaded) {
		t.Fatal("stale load granted", err)
	}
	loaded.DefaultRouteConsent.Digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	raw, _ = json.Marshal(loaded)
	if _, _, err := InspectBytes(raw); !errors.Is(err, ErrDefaultRouteConsent) {
		t.Fatal("corrupt declared approval normalized away", err)
	}
}

func TestDefaultConsentStorageCancelledWriteAndCanonicalProtocol(t *testing.T) {
	s, _ := networkCommitFixture(t)
	before := s.Get()
	p := CloneNetworkPolicy(before.NetworkPolicy)
	p.Revision++
	p.Traffic = TrafficSelection{Mode: "selected_services", Unavailable: "retain"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ApproveDefaultRouteConsent(ctx, before, p, []DefaultRouteGrant{consentConfigGrant()}, "0123456789abcdef0123456789abcdef", 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("cancelled approval wrote")
	}
	g := DefaultRouteGrant{Resolved: "xray:node-test", ProviderClass: "node", ProviderID: "node-test", SourceIDs: []string{"manual"}, SourceKinds: []string{"manual"}, Protocols: []string{"shadowsocks"}}
	if err := ValidateDefaultRouteGrant(g); err != nil {
		t.Fatal("canonical private type refused", err)
	}
	g.Protocols = []string{"ss"}
	if err := ValidateDefaultRouteGrant(g); err == nil {
		t.Fatal("display/URI alias accepted as canonical type")
	}
}

func TestSelectedScopeApprovalAllowsNoProvidersAndSurvivesOnlySameClients(t *testing.T) {
	s, _ := networkCommitFixture(t)
	before := s.Get()
	p := CloneNetworkPolicy(before.NetworkPolicy)
	p.Revision++
	p.Traffic = TrafficSelection{Mode: "selected_services", Unavailable: "retain"}
	if _, err := s.ApproveDefaultRouteConsent(context.Background(), before, p, nil, "0123456789abcdef0123456789abcdef", 1); err != nil {
		t.Fatal("scope-only explicit approval", err)
	}
	approved := s.Get()
	if !CurrentDefaultRouteScopeConsent(approved) || !CurrentDefaultRouteConsent(approved) || len(approved.DefaultRouteConsent.Grants) != 0 {
		t.Fatal("scope-only approval fabricated provider permission")
	}
	manual := []ResourceMatch{{Kind: "cidr", Value: "203.0.113.0/24"}}
	if _, err := s.UpdateResourceExclusions(context.Background(), approved, &manual, nil); err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	if CurrentDefaultRouteConsent(after) || !CurrentDefaultRouteScopeConsent(after) || after.DefaultRouteConsent.Digest != approved.DefaultRouteConsent.Digest {
		t.Fatal("resource edit renewed exact review or revoked unchanged scope")
	}
	if err := s.UpdateService("local", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if !CurrentDefaultRouteScopeConsent(s.Get()) {
		t.Fatal("active list edit expanded unchanged approved clients")
	}
	for _, change := range []string{"segment", "device", "device-exclusion", "inherit", "mode", "future", "legacy"} {
		t.Run(change, func(t *testing.T) {
			cfg := s.Get()
			switch change {
			case "segment":
				cfg.NetworkPolicy.Clients.SegmentIDs = append(cfg.NetworkPolicy.Clients.SegmentIDs, "guest")
			case "device":
				cfg.NetworkPolicy.Clients.DeviceIDs = []string{"new-device"}
			case "device-exclusion":
				cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"new-device"}
			case "inherit":
				cfg.NetworkPolicy.Clients.NewDevices = "base"
			case "mode":
				cfg.NetworkPolicy.Traffic.Mode = "all_except"
				cfg.NetworkPolicy.Traffic.AllExceptAllowed = true
			case "future":
				cfg.DefaultRouteConsent.ConfigRevision = cfg.Revision + 1
			case "legacy":
				cfg.DefaultRouteConsent.Schema = 1
				cfg.DefaultRouteConsent.Policy.Traffic.Mode = "all_except"
				cfg.DefaultRouteConsent.Policy.Traffic.AllExceptAllowed = true
				cfg.DefaultRouteConsent.Grants = []DefaultRouteGrant{consentConfigGrant()}
				cfg.DefaultRouteConsent.Digest = DefaultRouteConsentDigest(cfg.DefaultRouteConsent)
			}
			if CurrentDefaultRouteScopeConsent(cfg) {
				t.Fatal("changed or historical client scope inherited approval")
			}
		})
	}
}
