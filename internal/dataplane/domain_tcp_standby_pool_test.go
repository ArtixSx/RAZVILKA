package dataplane

import (
	"context"
	"slices"
	"testing"
	"time"
)

// These comparison models issue no original standby, native source, forward
// admission or cleanup authority. A returned retry pointer still has to pass
// the real writer/old owner/kernel/fleet/guard bookends before any callback.
func TestDomainPoolInitialRetryRequiresSameLiveUnenteredRequest(t *testing.T) {
	for _, change := range []string{"none", "different-request", "copied-cursor", "entered", "resource", "finished", "canceled", "closed-scope", "foreign-holder"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			plan := domainTCPProofPlanModel(t)
			m := New(t.TempDir())
			d := &DomainTCPDetachedStandby{}
			d.self = d
			pool := &domainTCPStandbyPool{manager: m, entries: []*domainTCPStandbyPoolEntry{{detached: d}}}
			pool.self = pool
			m.domainPool = pool
			s := &executionResourceScope{manager: m, plan: plan, execution: &Execution{State: "checking"}, open: true}
			s.observationOpen.Store(true)
			r := &xraySelectedTCPExecutionRecords{scope: s}
			c := &domainTCPGlobalSuccessor{pool: pool, scope: s, records: r, request: ctx, pending: true}
			c.self = c
			pool.successor = c
			s.domainSuccessor = c
			passed := context.Context(ctx)
			switch change {
			case "different-request":
				passed = context.WithValue(ctx, struct{ different string }{"request"}, true)
			case "copied-cursor":
				c.self = &domainTCPGlobalSuccessor{}
			case "entered":
				c.actionStarted = true
			case "resource":
				s.execution.Resources = []ExecutionResource{{ID: "existing"}}
			case "finished":
				s.execution.State = "temporary-complete"
			case "canceled":
				cancel()
			case "closed-scope":
				s.observationOpen.Store(false)
			case "foreign-holder":
				r.scope = &executionResourceScope{}
			}
			got, err := m.originalDomainPublicationRetry(passed, plan, d)
			if change == "none" {
				if err != nil || got != c {
					t.Fatal("same unentered comparison cursor lost", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("new/replayed request borrowed original retry", change)
			}
		})
	}
}

func TestDomainPoolCounterfactualOnlyRemovesExactCompleteBaseline(t *testing.T) {
	plan, rows := syntheticBaselineKernelModel(t)
	foreign := backendInventoryRow{Family: 4, Table: "filter", Tokens: []string{"-A", "FORWARD", "-j", "DROP"}}
	rows = append(rows, foreign)
	filtered, err := domainTCPRetainedBaselineRows(rows, plan)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range filtered {
		if r.Family == foreign.Family && r.Table == foreign.Table && slices.Equal(r.Tokens, foreign.Tokens) {
			found = true
		}
	}
	if !found {
		t.Fatal("comparison removed unrelated policy")
	}
	for _, change := range []string{"missing", "duplicate", "extra-body", "wrong-family", "foreign-reference"} {
		t.Run(change, func(t *testing.T) {
			copy := append([]backendInventoryRow(nil), rows...)
			for i := range copy {
				copy[i].Tokens = slices.Clone(copy[i].Tokens)
			}
			chain := plan.Effects[0].Add[3]
			own := -1
			for i, row := range copy {
				if len(row.Tokens) == 2 && row.Tokens[0] == "-N" && row.Tokens[1] == chain {
					own = i
				}
			}
			if own < 0 {
				t.Fatal("fixture has no actual baseline chain")
			}
			switch change {
			case "missing":
				copy = append(copy[:own], copy[own+1:]...)
			case "duplicate":
				copy = append(copy, copy[own])
			case "extra-body":
				copy = append(copy, backendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", chain, "-j", "RETURN"}})
			case "wrong-family":
				copy[own].Family = 6
			case "foreign-reference":
				copy = append(copy, backendInventoryRow{Family: 4, Table: "filter", Tokens: []string{"-A", "FORWARD", "-j", chain}})
			}
			if _, err := domainTCPRetainedBaselineRows(copy, plan); err == nil {
				t.Fatal("foreign/incomplete footprint disappeared", change)
			}
		})
	}
}
