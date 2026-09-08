package enginelab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestPolicyConflictInspectionRecognizesOnlyRegisteredExactExclusion(t *testing.T) {
	root := t.TempDir()
	manager := dataplane.New(filepath.Join(root, "configured-dataplane"))
	adapter, err := dataplane.NewProxyTunnelAdapter("sing-box", engineconfig.New(filepath.Join(root, "drafts"), filepath.Join(root, "backups")), filepath.Join(root, "registered-state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	state := dataplane.PolicyState{Interface: "rz-sing", Table: 203, PriorityBase: 22000, Prefixes: []string{"198.51.100.20/32"}, Exclusions: []string{"203.0.113.9/32", "2001:db8::9/128"}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(adapter.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adapter.StateRoot, "policy.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	rules := []string{"22000: from all to 203.0.113.9 lookup main\n", "22001: from all to 2001:db8::9 lookup main\n"}
	if conflicts := policyConflictsFromState(rules, nil); len(conflicts) != 2 {
		t.Fatalf("without authority both main exclusions must conflict: %+v", conflicts)
	}
	if conflicts := policyConflictsFromStateWithOwner(rules, nil, manager.OwnsProxyEndpointExclusion); len(conflicts) != 0 {
		t.Fatalf("own exact main exclusions blocked node switch: %+v", conflicts)
	}
	for _, line := range []string{
		"22000: from all to 203.0.113.10 lookup main",
		"22000: from 192.168.1.40 to 203.0.113.9 lookup main",
		"22000: from all to 203.0.113.9 fwmark 0x1 lookup main",
		"22000: from all to 203.0.113.9 lookup main suppress_prefixlength 0",
		"22002: from all to 203.0.113.9 lookup main",
		"22000: from all to 203.0.113.9 lookup 999",
	} {
		withForeign := []string{rules[0] + line + "\n", rules[1]}
		conflicts := policyConflictsFromStateWithOwner(withForeign, nil, manager.OwnsProxyEndpointExclusion)
		if len(conflicts) != 1 || !conflicts[0].Blocking || conflicts[0].Kind != "priority" {
			t.Fatalf("near-match foreign rule was hidden: line=%q conflicts=%+v", line, conflicts)
		}
	}
}
