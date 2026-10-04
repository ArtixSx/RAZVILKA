package config

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReviewedWireGuardAssignmentCASPreservesOrdinaryPolicyFence(t *testing.T) {
	s, policy := policyStore(t)
	if _, err := s.UpdateServicePolicy(policy, s.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	state := ServiceState{Enabled: true, Route: "wireguard:backup", WireGuardProfileRevision: strings.Repeat("a", 64), Sources: []string{"192.168.1.40"}}
	if err := s.UpdateServiceIfRevision("telegram", state, before.Revision); err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	fenced := after.ServicePolicies["telegram"]
	if after.Revision != before.Revision+1 || after.Services["telegram"].WireGuardProfileRevision != state.WireGuardProfileRevision ||
		fenced.Enabled || fenced.Mode != "manual" || fenced.Revision != before.ServicePolicies["telegram"].Revision+1 ||
		!reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || after.AppliedRevision != before.AppliedRevision {
		t.Fatal("reviewed assignment bypassed draft CAS or policy fence")
	}
	disk, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateServiceIfRevision("telegram", ServiceState{Route: "direct"}, before.Revision); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale whole config accepted", err)
	}
	current, err := os.ReadFile(s.path)
	if err != nil || string(current) != string(disk) || !reflect.DeepEqual(s.Get(), after) {
		t.Fatal("stale CAS changed configuration or automatic permission")
	}
	loaded, err := Load(s.path)
	if err != nil || !reflect.DeepEqual(loaded.Get(), after) {
		t.Fatal("reviewed binding did not persist", err)
	}
}

func TestWireGuardBindingShapeRefusesMalformedAndForeignRouteMetadata(t *testing.T) {
	for _, state := range []ServiceState{
		{Route: "wireguard:backup", WireGuardProfileRevision: strings.Repeat("A", 64)},
		{Route: "wireguard:backup", WireGuardProfileRevision: "a"},
		{Route: "wireguard:main", WireGuardProfileRevision: strings.Repeat("a", 64)},
		{Route: "wireguard", WireGuardProfileRevision: strings.Repeat("a", 64)},
		{Route: "xray:backup", WireGuardProfileRevision: strings.Repeat("a", 64)},
	} {
		if err := validateServiceProfileBinding(state); !errors.Is(err, ErrWireGuardProfileBinding) {
			t.Fatal("invalid profile binding shape accepted")
		}
		for _, scope := range []string{"draft", "applied", "suspended"} {
			cfg := Default()
			cfg.AppliedServices = map[string]ServiceState{}
			switch scope {
			case "draft":
				cfg.Services["telegram"] = state
			case "applied":
				cfg.AppliedServices["telegram"] = state
			case "suspended":
				cfg.ServiceControl.Stopped = true
				cfg.ServiceControl.SuspendedServices = map[string]ServiceState{"telegram": state}
			}
			data, _ := json.Marshal(cfg)
			if _, _, err := InspectBytes(data); !errors.Is(err, ErrWireGuardProfileBinding) {
				t.Fatal("retained malformed binding accepted", scope, err)
			}
		}
	}
	if err := validateServiceProfileBinding(ServiceState{Route: "wireguard:legacy"}); err != nil {
		t.Fatal("legacy preview intent became unreadable")
	}
}

func TestWireGuardBindingCannotBypassShapeThroughDraftImports(t *testing.T) {
	for _, replace := range []bool{false, true} {
		s, _ := policyStore(t)
		before := s.Get()
		bad := map[string]ServiceState{"telegram": {Route: "direct", WireGuardProfileRevision: strings.Repeat("a", 64)}}
		var err error
		if replace {
			err = s.ReplaceDraft(bad)
		} else {
			err = s.MergeDraft(bad)
		}
		if !errors.Is(err, ErrWireGuardProfileBinding) || !reflect.DeepEqual(before, s.Get()) {
			t.Fatal("draft import persisted invalid profile binding", replace, err)
		}
	}
}
