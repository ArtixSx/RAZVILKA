package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Definition models only: no listener, helper or kernel effects are created.
func TestDomainTransportSharedPlanClonesDigestsAndRemainsClosed(t *testing.T) {
	transport, domain := syntheticTransportModelFixture(t)
	input := Input{Revision: 7, DomainPolicy: domain, SyntheticDNS: transport}
	plan, err := BuildAt(input, time.Unix(100, 0).UTC())
	if err != nil || plan.Ready || plan.Noop || !plan.RequiresNetworkProof() {
		t.Fatal("intent became runtime authority", plan.Ready, plan.Noop, err)
	}
	data, err := json.Marshal(plan)
	var retained Plan
	if err != nil || json.Unmarshal(data, &retained) != nil {
		t.Fatal("retained definition unavailable", err)
	}
	d, s, err := retained.FrozenDomainTransport()
	if err != nil || d.Digest != domain.Digest || s.CaptureEndpoint != transport.CaptureEndpoint {
		t.Fatal("shared frozen definition changed", err)
	}
	s.Definition.ExactNames[0] = "changed.example.com"
	d.Services[0].Domains[0] = "changed.example.com"
	clone := cloneExecutionResourcePlan(plan)
	clone.DomainPolicy.Services[0].Domains[0] = "clone.example.com"
	clone.SyntheticDNS.DNS.Bindings[0].Domain = "clone.example.com"
	transport.Definition.ExactNames[0] = "input.example.com"
	domain.Services[0].Domains[0] = "input.example.com"
	if _, _, err := plan.FrozenDomainTransport(); err != nil || plan.SyntheticDNS.Definition.ExactNames[0] != "service.example.com" {
		t.Fatal("caller or resource clone changed original plan", err)
	}

	changed := CloneSyntheticDNSTransportPlan(plan.SyntheticDNS)
	changed.CaptureEndpoint = "192.168.1.1:10444"
	other, err := BuildAt(Input{Revision: 7, DomainPolicy: plan.DomainPolicy, SyntheticDNS: changed}, time.Unix(100, 0).UTC())
	if err != nil || other.Digest == plan.Digest {
		t.Fatal("synthetic definition absent from route digest", err)
	}
	base, err := BuildAt(Input{DomainPolicy: plan.DomainPolicy}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	changedDomain := CloneDomainPolicyRuntimePlan(plan.DomainPolicy)
	changedDomain.Scope.ObservedAt = changedDomain.Scope.ObservedAt.Add(time.Second)
	changedDomain.Digest = domainPolicyRuntimeDigest(changedDomain)
	other, err = BuildAt(Input{DomainPolicy: changedDomain}, time.Unix(100, 0).UTC())
	if err != nil || other.Digest == base.Digest {
		t.Fatal("domain definition absent from route digest", err)
	}
}

func TestDomainTransportSharedPlanRefusesPartialAndMixedDefinitions(t *testing.T) {
	for _, kind := range []string{"missing-domain", "legacy", "suspend", "discard", "changed-digest"} {
		t.Run(kind, func(t *testing.T) {
			transport, domain := syntheticTransportModelFixture(t)
			input := Input{DomainPolicy: domain, SyntheticDNS: transport}
			switch kind {
			case "missing-domain":
				input.DomainPolicy = nil
			case "legacy":
				input.DNS = &ScopedDNSPlan{}
			case "suspend":
				input.SuspendDNS = true
			case "discard":
				input.DiscardDNS = true
			case "changed-digest":
				input.DomainPolicy.Services[0].Domains[0] = "changed.example.com"
			}
			if _, err := BuildAt(input, time.Unix(100, 0).UTC()); err == nil {
				t.Fatal("unbound definition accepted")
			}
		})
	}
}

func TestDomainTransportManagerRefusesDecodedReadinessBeforeEffects(t *testing.T) {
	transport, domain := syntheticTransportModelFixture(t)
	plan, err := BuildAt(Input{DomainPolicy: domain, SyntheticDNS: transport}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.Ready, plan.Blockers, plan.Adapters = true, nil, []string{scopedDNSAdapterID}
	m := New(filepath.Join(t.TempDir(), "dataplane"))
	adapter := &fakeAdapter{id: scopedDNSAdapterID}
	if err := m.Register(adapter); err != nil {
		t.Fatal(err)
	}
	committed := false
	execution, err := m.Apply(context.Background(), plan, func() (func() error, error) {
		committed = true
		return nil, nil
	})
	if !errors.Is(err, ErrDomainTransportRuntime) || committed || len(adapter.calls) != 0 || len(execution.Steps) != 0 {
		t.Fatal("decoded readiness bypassed original runtime owner", err, committed, adapter.calls)
	}
}
