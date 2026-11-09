package dataplane

import (
	"strings"
	"testing"
)

// Real original journal descriptors; process/kernel retirement is modeled.
// A retained reader9 terminal header still binds its exact owned live row.
func mihomoRetiredHeaderClosingScopeModel(t *testing.T) (*executionResourceScope, *mihomoLiveResource) {
	t.Helper()
	m, _, r, _ := mihomoLiveRecordModel(t)
	if err := m.retainOriginalMihomo(r.scope, false); err != nil {
		t.Fatal(err)
	}
	s := r.scope
	s.execution.State = "rolled-back"
	s.execution.Resources[0].State, s.execution.Resources[0].Phase = "removed", "removed"
	s.execution.MihomoLiveHealthOperation = &ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("b", 64), PlanID: s.execution.PlanID, PlanDigest: s.execution.Digest, BeforeSHA256: strings.Repeat("c", 64), Phase: "retired"}
	if err := validateExecutionResources(*s.execution, true); err != nil {
		t.Fatal("invalid original terminal fixture", err)
	}
	r.retired = true
	terminal := &MihomoLiveTerminal{owner: r}
	terminal.self = terminal
	r.terminal = terminal
	if _, err := r.newClosing(terminal, false); err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestMihomoRetiredHealthHeaderScopeCloseKeepsOriginalOwnedRow(t *testing.T) {
	s, _ := mihomoRetiredHeaderClosingScopeModel(t)
	if err := s.close(); err != nil {
		t.Fatal("retired original reader9 terminal rejected at scope close", err)
	}
	if s.open || s.closedErr != nil {
		t.Fatal("successful original scope close not retained")
	}
}

func TestMihomoRetiredHealthHeaderScopeCloseRejectsForeignOwner(t *testing.T) {
	for _, name := range []string{"copied-owner", "foreign-scope", "changed-id", "changed-definition", "missing-row", "active-row"} {
		t.Run(name, func(t *testing.T) {
			s, r := mihomoRetiredHeaderClosingScopeModel(t)
			switch name {
			case "copied-owner":
				s.mihomoLive = &mihomoLiveResource{self: r, scope: s, adapter: r.adapter, id: r.id, definition: r.definition, records: r.records}
			case "foreign-scope":
				r.scope = &executionResourceScope{}
			case "changed-id":
				r.id = "ml-" + strings.Repeat("f", 32)
			case "changed-definition":
				r.definition.Plan.Revision++
			case "missing-row":
				s.execution.Resources = nil
			case "active-row":
				s.execution.Resources[0].State, s.execution.Resources[0].Phase = "active", "active"
			}
			if err := s.close(); err == nil {
				t.Fatal("foreign or nonterminal original owner accepted")
			}
			if s.execution.MihomoLiveHealthOperation == nil {
				t.Fatal("terminal header erased to bypass validation")
			}
		})
	}
}
