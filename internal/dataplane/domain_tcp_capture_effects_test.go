package dataplane

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestDomainTCPCaptureClosedEffectsAuthenticateWholeOwnedInventory(t *testing.T) {
	d := xrayDomainExecutionDefinitionFixture(t)
	plan, err := compileDomainTCPCaptureEffects(d.Capture, d.Mapping)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]backendInventoryRow, len(plan.Effects))
	for i, e := range plan.Effects {
		rows[i], err = domainTCPCaptureEffectRow(e)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range plan.Effects {
		if count, err := domainTCPCapturePresence(rows, plan, i); err != nil || count != 1 {
			t.Fatal(i, count, err)
		}
	}
	// -I 1 means the final two selectors appear in reverse creation order.
	rows[5], rows[6] = rows[6], rows[5]
	if err := domainTCPCapturePreparedInventory(rows, plan); err != nil {
		t.Fatal(err)
	}
	shadow := backendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "PREROUTING", "-j", "ACCEPT"}}
	if err := domainTCPCapturePreparedInventory(append([]backendInventoryRow{shadow}, rows...), plan); err == nil {
		t.Fatal("shadowed capture declared ready")
	}
	filtered, err := domainTCPCaptureBaselineRows(append([]backendInventoryRow{shadow}, rows...), plan)
	if err != nil || len(filtered) != 1 || !slices.Equal(filtered[0].Tokens, shadow.Tokens) {
		t.Fatal("counterfactual view removed foreign rows", err)
	}
	for _, mutation := range []string{"duplicate", "foreign-body", "foreign-reference", "foreign-family"} {
		t.Run(mutation, func(t *testing.T) {
			altered := slices.Clone(rows)
			foreign := backendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", plan.Effects[0].Add[3], "-j", "ACCEPT"}}
			switch mutation {
			case "duplicate":
				altered = append(altered, rows[5])
			case "foreign-body":
				altered = append(altered, foreign)
			case "foreign-reference":
				foreign.Tokens = []string{"-A", "OUTPUT", "-j", plan.Effects[0].Add[3]}
				altered = append(altered, foreign)
			case "foreign-family":
				foreign = rows[5]
				foreign.Family = 6
				altered = append(altered, foreign)
			}
			if _, err := domainTCPCapturePresence(altered, plan, 0); err == nil {
				t.Fatal("foreign ownership accepted")
			}
			if _, err := domainTCPCaptureBaselineRows(altered, plan); err == nil {
				t.Fatal("counterfactual view hid foreign owner")
			}
		})
	}
	// The selector is the reservation's synthetic address, never its real CDN.
	d.Mapping.Synthetic = d.Mapping.RealIPv4
	if _, err := compileDomainTCPCaptureEffects(d.Capture, d.Mapping); err == nil {
		t.Fatal("public destination capture admitted")
	}
}

func TestDomainTCPResourceConsumerAndAcceptedSocketRejectReconstruction(t *testing.T) {
	ctx := context.Background()
	for _, resource := range []*XrayDomainTCPExecutionResource{nil, {}, {self: &XrayDomainTCPExecutionResource{}}} {
		if err := (&ProxyTunnelAdapter{}).RunDomainPolicyTCPResource(ctx, resource, nil); err == nil {
			t.Fatal("reconstructed resource entered consumer")
		}
	}
	socket := DomainPolicyTCPSocket{Source: netip.MustParseAddrPort("192.168.1.2:1234")}
	if _, err := originalDomainAcceptedTCP(ctx, nil, socket); err == nil {
		t.Fatal("tuple manufactured FD carrier")
	}
	a := &domainAcceptedTCP{socket: socket}
	a.self = a
	a.open.Store(true)
	if _, err := originalDomainAcceptedTCP(context.WithValue(ctx, domainAcceptedTCPKey{}, a), nil, socket); err == nil {
		t.Fatal("missing actual accepted socket admitted")
	}
}

func TestDomainTCPCaptureRetainedIntentNeverGrantsActiveOrSettledOwnership(t *testing.T) {
	d := xrayDomainExecutionDefinitionFixture(t)
	plan, err := compileDomainTCPCaptureEffects(d.Capture, d.Mapping)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := PolicyEffectPlanDigest(plan)
	definition := ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: d}
	r := ExecutionResource{ID: "dc-" + strings.Repeat("a", 32), Kind: "domain-tcp-capture", State: "prepared", Phase: "planned", Generation: plan.Generation, EffectsDigest: digest, DomainTCPCapture: &definition}
	e := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, Resources: []ExecutionResource{r}}
	for _, phase := range []string{"planned", "capture-prepared", "closed"} {
		e.Resources[0].Phase = phase
		if validateExecutionResources(e, false) != nil || validateExecutionResources(e, true) == nil {
			t.Fatal("pending capture became terminal", phase)
		}
	}
	e.Resources[0].State = "active"
	e.Resources[0].Phase = "active"
	if validateExecutionResources(e, false) == nil {
		t.Fatal("capture intent granted active route")
	}
	e.Resources[0] = r
	e.Resources[0].EffectsDigest = strings.Repeat("f", 64)
	if validateExecutionResources(e, false) == nil {
		t.Fatal("foreign capture effects digest accepted")
	}
	clone := cloneExecutionResources([]ExecutionResource{r})
	clone[0].DomainTCPCapture.Process.Domain.Services[0].Domains[0] = "changed.example"
	if d.Domain.Services[0].Domains[0] == "changed.example" {
		t.Fatal("capture clone changed original plan")
	}
}

func TestDomainTCPCaptureCounterfactualRequiresEveryOriginalReceiptState(t *testing.T) {
	d := xrayDomainExecutionDefinitionFixture(t)
	plan, err := compileDomainTCPCaptureEffects(d.Capture, d.Mapping)
	if err != nil {
		t.Fatal(err)
	}
	states := make([]string, len(plan.Effects))
	for i := range states {
		states[i] = "planned"
	}
	var rows []backendInventoryRow
	if err := domainTCPCaptureReceiptMatchesRows(rows, plan, states); err != nil {
		t.Fatal(err)
	}
	for i, effect := range plan.Effects {
		row, err := domainTCPCaptureEffectRow(effect)
		if err != nil {
			t.Fatal(err)
		}
		// An exact foreign object at a planned index is still unowned.
		foreign := append(slices.Clone(rows), row)
		if err := domainTCPCaptureReceiptMatchesRows(foreign, plan, states); err == nil {
			t.Fatal("planned foreign exact row hidden", i)
		}
		states[i] = "intent"
		if err := domainTCPCaptureReceiptMatchesRows(rows, plan, states); err != nil {
			t.Fatal("intent absence refused", i, err)
		}
		if err := domainTCPCaptureReceiptMatchesRows(foreign, plan, states); err == nil {
			t.Fatal("unacknowledged exact row hidden", i)
		}
		states[i] = "added"
		rows = foreign
		if err := domainTCPCaptureReceiptMatchesRows(rows, plan, states); err != nil {
			t.Fatal("acknowledged partial state refused", i, err)
		}
	}
	for _, state := range []string{"intent", "cleanup-intent", "removed", "unknown"} {
		changed := slices.Clone(states)
		changed[0] = state
		if err := domainTCPCaptureReceiptMatchesRows(rows, plan, changed); err == nil {
			t.Fatal("pending/unknown/cleanup hidden", state)
		}
	}
	if err := domainTCPCaptureReceiptMatchesRows(rows[1:], plan, states); err == nil {
		t.Fatal("lost acknowledged parent hidden")
	}
}
