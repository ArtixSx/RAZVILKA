package dataplane

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Complete kernel-image models test the comparison only; none constructs a
// resource, COMMON writer, native owner or admission permission.
func xraySelectedTCPOrderFixture(t *testing.T) (BackendInventorySnapshot, networkPolicyXraySelectedTCPObservation) {
	t.Helper()
	plan, err := CompileXraySelectedTCPRedirect(xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64)))
	if err != nil {
		t.Fatal(err)
	}
	states := make([]string, len(plan.Effects))
	for i := range states {
		states[i] = "added"
	}
	rows, required, err := xraySelectedTCPReceiptRows(plan, states, false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nfqwsDirectStockReviewedVendorFixture()
	var selectors []BackendInventoryRow
	for _, row := range rows {
		if row.Tokens[1] == "PREROUTING" {
			selectors = append([]BackendInventoryRow{row}, selectors...)
		} else {
			snapshot.Rows = append(snapshot.Rows, row)
		}
	}
	snapshot.Rows = append(snapshot.Rows, selectors...)
	return snapshot, networkPolicyXraySelectedTCPObservation{rows: rows, required: required}
}

func TestXraySelectedTCPInventoryOrderRejectsSemanticReordering(t *testing.T) {
	snapshot, observation := xraySelectedTCPOrderFixture(t)
	before := nfqwsDirectStockTestClone(snapshot)
	if err := xraySelectedTCPInventoryOrder(snapshot, []networkPolicyXraySelectedTCPObservation{observation}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshot) {
		t.Fatal("comparison changed capture")
	}
	for _, change := range []string{"negative-after-redirect", "selectors-in-add-order", "duplicate-body", "foreign-body", "required-absent", "incomplete"} {
		t.Run(change, func(t *testing.T) {
			s := nfqwsDirectStockTestClone(snapshot)
			var body, selectors []int
			for i, row := range s.Rows {
				if !networkPolicyXraySelectedTCPRow(row) || row.Tokens[0] != "-A" {
					continue
				}
				if row.Tokens[1] == "PREROUTING" {
					selectors = append(selectors, i)
				} else {
					body = append(body, i)
				}
			}
			switch change {
			case "negative-after-redirect":
				s.Rows[body[0]], s.Rows[body[3]] = s.Rows[body[3]], s.Rows[body[0]]
			case "selectors-in-add-order":
				s.Rows[selectors[0]], s.Rows[selectors[1]] = s.Rows[selectors[1]], s.Rows[selectors[0]]
			case "duplicate-body":
				s.Rows = append(s.Rows, s.Rows[body[0]])
			case "foreign-body":
				s.Rows = append(s.Rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-A", "RZX_foreign", "-j", "RETURN"}})
			case "required-absent":
				s.Rows = slices.Delete(s.Rows, body[0], body[0]+1)
			case "incomplete":
				s.Coverage.RegisteredTablesComplete = false
			}
			if err := xraySelectedTCPInventoryOrder(s, []networkPolicyXraySelectedTCPObservation{observation}); err == nil {
				t.Fatal("unsafe order accepted", change)
			}
		})
	}
}

func TestXraySelectedTCPInventoryOrderOnlyActualPendingMayBeAbsent(t *testing.T) {
	snapshot, observation := xraySelectedTCPOrderFixture(t)
	// Last effect is inserted first in PREROUTING. Its actual writer may be
	// between intent and syscall ACK. All earlier added rows stay required.
	observation.required = slices.Clone(observation.required)
	observation.required[len(observation.required)-1] = false
	if err := xraySelectedTCPInventoryOrder(snapshot, []networkPolicyXraySelectedTCPObservation{observation}); err != nil {
		t.Fatal("pending row present", err)
	}
	first := -1
	for i, row := range snapshot.Rows {
		if networkPolicyXraySelectedTCPRow(row) && row.Tokens[1] == "PREROUTING" {
			first = i
			break
		}
	}
	snapshot.Rows = slices.Delete(snapshot.Rows, first, first+1)
	if err := xraySelectedTCPInventoryOrder(snapshot, []networkPolicyXraySelectedTCPObservation{observation}); err != nil {
		t.Fatal("pending row absent", err)
	}
	observation.required[len(observation.required)-1] = true
	if err := xraySelectedTCPInventoryOrder(snapshot, []networkPolicyXraySelectedTCPObservation{observation}); err == nil {
		t.Fatal("missing added selector accepted")
	}
}
