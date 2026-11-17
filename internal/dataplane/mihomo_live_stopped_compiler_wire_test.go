package dataplane

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// Reproduces the stopped-original-intent comparison using actual compiler
// output and the Manager's published document, without native authority.
func mihomoStoppedCompilerWireFixture(t *testing.T) (Plan, Plan) {
	t.Helper()
	d := mihomoLiveDefinitionFixture(t)
	plan, err := BuildAt(Input{
		Revision: 1, NetworkProfileID: d.NetworkProfile,
		Routes:  d.Plan.Routes,
		Engines: []Engine{{ID: "mihomo", Installed: true, Configured: true, Activatable: true, Canary: true}},
		Host:    HostState{IPCommand: true, IPTables: true, IP6Tables: true, TUN: true, SingBox: true, OffloadState: "disabled"},
	}, time.Unix(100, 0).UTC())
	if err != nil || !plan.Ready {
		t.Fatal("compiler fixture not ready", err, plan.Blockers)
	}
	frozen := cloneExecutionResourcePlan(plan)
	plan.State, plan.Note = "committed", "actual result bookkeeping"
	m := New(t.TempDir())
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	actual, found, err := m.Committed()
	if err != nil || !found {
		t.Fatal(err)
	}
	return frozen, actual
}

func TestMihomoStoppedOriginalIntentCompilerWireRoundTrip(t *testing.T) {
	frozen, actual := mihomoStoppedCompilerWireFixture(t)
	before, _ := json.Marshal(frozen)
	currentBefore, _ := json.Marshal(actual)
	if !mihomoStoppedOriginalPlanMatches(frozen, actual) {
		t.Fatal("stopped original intent rejects its own compiler wire image")
	}
	after, _ := json.Marshal(frozen)
	currentAfter, _ := json.Marshal(actual)
	if string(before) != string(after) || string(currentBefore) != string(currentAfter) {
		t.Fatal("comparison mutated original intent or published document")
	}
	var ownWire Plan
	if err := json.Unmarshal(before, &ownWire); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(ownWire)
	if string(before) != string(encoded) || reflect.DeepEqual(frozen, ownWire) {
		t.Fatal("fixture did not preserve exact bytes across compiler/wire shape difference")
	}
}

func TestMihomoStoppedOriginalIntentRejectsChangedWireIntent(t *testing.T) {
	for name, mutate := range map[string]func(*Plan){
		"schema":           func(p *Plan) { p.SchemaVersion++ },
		"plan":             func(p *Plan) { p.PlanID += "0" },
		"digest":           func(p *Plan) { p.Digest = "changed" },
		"revision":         func(p *Plan) { p.Revision++ },
		"ready":            func(p *Plan) { p.Ready = false },
		"network":          func(p *Plan) { p.NetworkProfileID = "changed" },
		"adapters":         func(p *Plan) { p.Adapters = []string{"xray"} },
		"retiring":         func(p *Plan) { p.RetiringAdapters = []string{"xray"} },
		"route":            func(p *Plan) { p.Routes[0].Resolved = "direct" },
		"destinations":     func(p *Plan) { p.Routes[0].CIDRs = []string{"0.0.0.0/0"} },
		"sources":          func(p *Plan) { p.Routes[0].Sources = nil },
		"devices":          func(p *Plan) { p.Routes[0].SourceRefs = []string{"foreign-device"} },
		"ingress":          func(p *Plan) { p.Routes[0].Ingress = []string{"foreign0"} },
		"service":          func(p *Plan) { p.Routes[0].ProbeService.ID = "foreign" },
		"probe":            func(p *Plan) { p.Routes[0].ProbeURL = "https://foreign.invalid/" },
		"policy-reference": func(p *Plan) { p.Routes[0].WireGuardProfileRevision = "foreign" },
		"resource-intent":  func(p *Plan) { p.EngineDrafts = []string{"foreign"} },
		"exclusions": func(p *Plan) {
			p.SiteExclusions = &SiteExclusions{CIDRs: []string{"9.9.9.9/32"}}
		},
		"native-policy":     func(p *Plan) { p.LAN = &LANPolicyRuntimePlan{} },
		"evidence-identity": func(p *Plan) { p.RouteEvidence[0].ServiceID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			frozen, actual := mihomoStoppedCompilerWireFixture(t)
			mutate(&actual)
			if mihomoStoppedOriginalPlanMatches(frozen, actual) {
				t.Fatal("changed intent accepted")
			}
		})
	}
}
