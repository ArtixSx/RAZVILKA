package config

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestManagedNFQReleaseUpdateInspectedState(t *testing.T) {
	for _, tc := range []struct {
		name, route, mode, applied                              string
		desiredPolicy, appliedPolicy, enabled, stopped, refused bool
	}{
		{"legacy-nfq", "nfqws2", "", "present", false, false, true, false, false},
		{"applied-nfq", "nfqws2", "", "present", true, true, true, false, true},
		{"applied-policy-only", "nfqws2", "", "present", false, true, true, false, true},
		{"desired-policy-ambiguous", "nfqws2", "", "present", true, false, true, false, true},
		{"legacy-mode", "", "nfqws2", "present", true, true, true, false, true},
		{"auto", "auto", "", "present", true, true, true, false, true},
		{"empty-route", "", "", "present", true, true, true, false, true},
		{"missing-applied", "nfqws2", "", "missing", true, false, true, false, true},
		{"null-applied", "nfqws2", "", "null", true, false, true, false, true},
		{"draft-only", "nfqws2", "", "empty", true, false, true, false, false},
		{"stopped-empty", "nfqws2", "", "empty", true, true, true, true, false},
		{"stopped-contradictory", "nfqws2", "", "present", true, true, true, true, true},
		{"disabled", "nfqws2", "", "present", true, true, false, false, false},
		{"xray", "xray:node-one", "", "present", true, true, true, false, false},
		{"wireguard", "wireguard", "", "present", true, true, true, false, false},
		{"direct", "direct", "", "present", true, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.SchemaVersion = 0 // Exercise real normalization without migration writes.
			state := ServiceState{Enabled: tc.enabled, Route: tc.route, Mode: tc.mode}
			cfg.Services["service"] = state
			cfg.AppliedServices["service"] = state
			cfg.ServiceControl.Stopped = tc.stopped
			if tc.stopped && tc.applied == "empty" {
				cfg.ServiceControl.SuspendedServices = map[string]ServiceState{"service": state}
				cfg.ServiceControl.SuspendedRoutes = map[string]string{"service": "nfqws2"}
			}
			if tc.desiredPolicy {
				cfg.NetworkPolicy = networkPolicyFixture()
			}
			if tc.appliedPolicy {
				cfg.AppliedNetworkPolicy = networkPolicyFixture()
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatal(err)
			}
			switch tc.applied {
			case "missing":
				delete(raw, "applied_services")
			case "null":
				raw["applied_services"] = json.RawMessage("null")
			case "empty":
				raw["applied_services"] = json.RawMessage("{}")
			}
			b, err = json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			inspected, _, err := InspectBytes(b)
			if err != nil {
				t.Fatal(err)
			}
			before := cloneConfig(inspected)
			err = CheckManagedNFQReleaseUpdate(inspected)
			if errors.Is(err, ErrManagedNFQReleaseUpdate) != tc.refused || !reflect.DeepEqual(before, inspected) {
				t.Fatalf("refused=%v err=%v or input mutated", tc.refused, err)
			}
		})
	}
}
