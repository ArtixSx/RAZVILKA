package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func policyStore(t *testing.T) (*Store, ServicePolicy) {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := ServiceState{Enabled: true, Route: "sing-box:group-existing", Sources: []string{"192.168.1.40/32"}}
	if err = s.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	p := DefaultServicePolicy("telegram", s.Get().AppliedServices["telegram"])
	p.Enabled = true
	p.Mode = "auto"
	p.GroupID = "group-existing"
	p.AllowedNodeIDs = []string{"node-" + strings.Repeat("a", 64)}
	p.AllowedSourceIDs = []string{"manual"}
	p.TrustClasses = []string{"manual"}
	return s, p
}

func TestServicePolicyCASPersistsScopeWithoutApplying(t *testing.T) {
	s, p := policyStore(t)
	before := s.Get()
	saved, err := s.UpdateServicePolicy(p, before.Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	if saved.Revision != 1 || after.Revision != before.Revision+1 || !reflect.DeepEqual(after.AppliedServices, before.AppliedServices) || after.AppliedRevision != before.AppliedRevision {
		t.Fatal("policy settings applied a route")
	}
	p.Mode = "paused"
	if _, err = s.UpdateServicePolicy(p, before.Revision, 0); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale policy accepted")
	}
	p.DeviceSources = nil
	if _, err = s.UpdateServicePolicy(p, after.Revision, 1); !errors.Is(err, ErrServicePolicy) {
		t.Fatal("policy widened device scope")
	}
	loaded, err := Load(s.path)
	if err != nil || !reflect.DeepEqual(loaded.Get(), after) {
		t.Fatalf("policy reload: %v", err)
	}
	copy := s.Get()
	copy.ServicePolicies["telegram"].AllowedNodeIDs[0] = "changed"
	if s.Get().ServicePolicies["telegram"].AllowedNodeIDs[0] == "changed" {
		t.Fatal("Get aliases policy permissions")
	}
}

func TestServicePolicyMigrationPreservesAppliedOptInAndDoesNotInferTrust(t *testing.T) {
	s, p := policyStore(t)
	before := s.Get()
	if err := s.PreserveLegacyServicePolicies([]ServicePolicy{p}, before.Revision); err != nil {
		t.Fatal(err)
	}
	after := s.Get()
	saved := after.ServicePolicies["telegram"]
	if !saved.LegacyOptIn || !saved.Enabled || saved.Revision != 1 || after.Revision != before.Revision || !reflect.DeepEqual(before.AppliedServices, after.AppliedServices) {
		t.Fatal("legacy opt-in not preserved exactly")
	}
	p.AllowedSourceIDs = append(p.AllowedSourceIDs, "new-public-feed")
	if err := s.PreserveLegacyServicePolicies([]ServicePolicy{p}, after.Revision); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Get(), after) {
		t.Fatal("migration widened existing permission")
	}
	legacy := []byte(`{"schema_version":1,"services":{"telegram":{"enabled":true,"route":"auto"}},"applied_services":{"telegram":{"enabled":true,"route":"auto"}},"safe_mode":false}`)
	cfg, report, err := InspectBytes(legacy)
	if err != nil || report.ToSchema != 2 || len(cfg.ServicePolicies) != 0 {
		t.Fatal("schema migration invented auto policy/trust")
	}
}

func TestServicePolicyManualIntentFencesRevisionAndPermission(t *testing.T) {
	s, p := policyStore(t)
	p, err := s.UpdateServicePolicy(p, s.Get().Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldApplied := s.Get().AppliedServices
	state := s.Get().Services["telegram"]
	state.Route = "direct"
	if err = s.UpdateService("telegram", state); err != nil {
		t.Fatal(err)
	}
	next := s.Get().ServicePolicies["telegram"]
	if next.Enabled || next.Mode != "manual" || next.Revision != p.Revision+1 || !reflect.DeepEqual(s.Get().AppliedServices, oldApplied) {
		t.Fatal("manual intent not fenced without runtime mutation")
	}
}

func TestServicePolicyInvalidImportCannotPartiallyMutateMigration(t *testing.T) {
	s, p := policyStore(t)
	before := s.Get()
	bad := p
	bad.ServiceID = "other"
	bad.Scenario.Kind = "invalid"
	if err := s.PreserveLegacyServicePolicies([]ServicePolicy{p, bad}, before.Revision); err == nil {
		t.Fatal("accepted invalid policy")
	}
	if !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("failed migration changed memory")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	var disk Config
	if json.Unmarshal(data, &disk) != nil || len(disk.ServicePolicies) != 0 {
		t.Fatal("failed migration changed disk")
	}
}
