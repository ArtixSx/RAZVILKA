package dataplane

import (
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestDomainPolicyCatalogueNegativeCannotLoseUnknownDeviceIdentity(t *testing.T) {
	p, flow, now := domainPolicyFixture(t, nil)
	p.policy.Rules = []config.NetworkRule{{ID: "device-bank-exception", Revision: 1, Kind: "service", Value: "bank", Action: "direct", Mandatory: true, DeviceIDs: []string{"selected"}}}
	p.services = append(p.services, DomainPolicyService{ID: "bank", Route: "xray", Domains: []string{flow.Name}})
	compiled, err := CompileDomainPolicy(p.generation, p.policy, p.scope, nil, p.services, now)
	if err != nil {
		t.Fatal(err)
	}
	if decision := compiled.Decide(flow, now); decision.Kind != "baseline" {
		t.Fatal("known device exception was lost", decision)
	}
	flow.Client.MAC = "02:00:00:00:00:33"
	if decision := compiled.Decide(flow, now); decision.Kind != "refused" || decision.Reason != "RESOURCE_IDENTITY_UNAVAILABLE" {
		t.Fatal("unresolved catalogue exception became positive authority", decision)
	}
}
