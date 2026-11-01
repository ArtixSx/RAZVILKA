package dataplane

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestMihomoProbeDoesNotAdvertiseOrAcceptLiveLifecycle(t *testing.T) {
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	m := New(t.TempDir())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	want := AdapterLifecycleRegistration{Registered: true, IsolatedProbe: true}
	if got := m.AdapterLifecycleRegistration("mihomo"); got != want {
		t.Fatalf("got %+v", got)
	}
	if m.Capable("mihomo") || m.CanaryCapable("mihomo") {
		t.Fatal("isolated probe became ordinary Apply/canary capability")
	}
	for _, action := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate, a.Activate, a.Health, a.Commit, a.Rollback} {
		if action(context.Background(), Plan{Ready: true}, t.TempDir()) == nil {
			t.Fatal("forged ready plan entered lifecycle")
		}
	}
	if a.Pending() || a.RetryCleanup(context.Background()) == nil {
		t.Fatal("missing original owner adopted")
	}
}

func TestMihomoProbeCoversEveryRequiredCatalogScenario(t *testing.T) {
	s := catalog.Service{ProbeURL: "https://example.com/primary", Probes: []catalog.Probe{
		{ID: "first", URL: "https://example.com/primary"},
		{ID: "required", URL: "https://example.com/api", Required: true, Expect: catalog.ProbeExpectation{JSON: true}},
		{ID: "optional", URL: "https://example.com/optional"},
	}}
	got := mihomoRequiredProbes(s)
	if len(got) != 2 || got[0].ID != "first" || !reflect.DeepEqual(got[1], s.Probes[1]) {
		t.Fatalf("lost required scenario: %+v", got)
	}
	s.Probes[0].Required = true
	if len(mihomoRequiredProbes(s)) != 2 {
		t.Fatal("primary run twice")
	}
	legacy := mihomoRequiredProbes(catalog.Service{ProbeURL: "https://www.youtube.com/generate_204"})
	if len(legacy) != 1 || !reflect.DeepEqual(legacy[0].Expect.StatusCodes, []int{204}) || legacy[0].Expect.RedirectPolicy != "none" {
		t.Fatal("legacy strict expectation lost")
	}
}

func TestMihomoPrivateProofNeverAcceptsAnApplyPlan(t *testing.T) {
	d := mihomoProbeDefinitionFixture(t)
	p := mihomoProbePlan(d)
	if err := validateMihomoProbePlan(p); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Plan){
		func(p *Plan) { p.Ready = true },
		func(p *Plan) { p.State = "ready" },
		func(p *Plan) { p.Routes[0].CIDRs = []string{"0.0.0.0/0"} },
		func(p *Plan) { p.Routes[0].Domains = []string{"example.com"} },
		func(p *Plan) { p.RetiringAdapters = []string{"xray"} },
	} {
		copy := cloneExecutionResourcePlan(p)
		change(&copy)
		if validateMihomoProbePlan(copy) == nil {
			t.Fatal("route mutation entered isolated proof")
		}
	}
}
