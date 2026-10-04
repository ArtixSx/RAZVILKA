package dataplane

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestDomainPolicyRuntimePlanRoundTripAndExpiredInventory(t *testing.T) {
	p, flow, now := domainPolicyFixture(t, nil)
	plan, err := FreezeDomainPolicyRuntimePlan(p.generation, p.policy, p.scope, p.guests, p.services, now)
	if err != nil {
		t.Fatal(err)
	}
	p.services[0].Domains[0] = "changed.example.com"
	copy := CloneDomainPolicyRuntimePlan(plan)
	copy.Services[0].Domains[0] = "other.example.com"
	if plan.Services[0].Domains[0] != "service.example.com" || ValidateDomainPolicyRuntimePlan(copy) == nil {
		t.Fatal("frozen/clone definition mutated")
	}
	wire, _ := json.Marshal(plan)
	var readback DomainPolicyRuntimePlan
	if json.Unmarshal(wire, &readback) != nil || ValidateDomainPolicyRuntimePlan(&readback) != nil {
		t.Fatal("retained definition does not survive JSON readback")
	}
	compiled, err := CompileDomainPolicyForPlan(&readback, now)
	if err != nil || compiled.Decide(flow, now).Kind != "service" {
		t.Fatal("fresh frozen definition changed decision", err)
	}
	if err := ValidateDomainPolicyRuntimePlan(&readback); err != nil {
		t.Fatal("expired inventory lost definition authority", err)
	}
	if _, err := CompileDomainPolicyForPlan(&readback, now.Add(3*time.Minute)); !errors.Is(err, ErrDomainPolicy) {
		t.Fatal("retained intent extended freshness", err)
	}
}
