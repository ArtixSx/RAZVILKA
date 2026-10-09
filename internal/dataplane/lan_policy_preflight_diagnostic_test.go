package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Actual pure preflight with explicit read-only RPDB/backend models; no effects.
func TestLANPolicyPreflightDiagnosticIdentifiesClosedRefusalWithoutChangingGuard(t *testing.T) {
	for _, test := range []struct{ ip, row, stage string }{
		{ip: "unknown private RPDB output\n", stage: "rpdb-syntax"},
		{ip: "53: from all lookup 254\n", stage: "rpdb-reserved-priority"},
		{ip: "100: from all goto 73\n", stage: "rpdb-goto-anchor"},
		{ip: "100: from all fwmark 0x28000000/0x28000000 lookup 4096\n", stage: "rpdb-gate-mark"},
		{ip: "28000: from all to 8.8.8.8 lookup 206\n", stage: "rpdb-owned-table"},
		{row: "-N RZG_private\n", stage: "table-owned-chain"},
		{row: "-A PREROUTING -j MARK --set-xmark 0x28000000/0x28000000\n", stage: "table-gate-mark"},
		{row: "-A PREROUTING -j CONNMARK --restore-mark\n", stage: "table-connmark"},
	} {
		t.Run(test.stage, func(t *testing.T) {
			reader := &lanRuntimeReadRunner{ip: map[string]string{"-4": test.ip}, firewall: map[string]string{"iptables:mangle": test.row}}
			err := runtimeWithReadRunner(reader).Preflight(context.Background(), lanRuntimeFixture(t))
			if !errors.Is(err, ErrLANPolicyRuntime) || LANPolicyPreflightFailureStage(errors.Join(errors.New("outer"), err)) != test.stage || err.Error() != ErrLANPolicyRuntime.Error() {
				t.Fatal("refusal changed or closed stage lost", err, LANPolicyPreflightFailureStage(err))
			}
			if strings.Contains(LANPolicyPreflightFailureStage(err), "private") {
				t.Fatal("native details leaked")
			}
		})
	}
	r := runtimeWithReadRunner(&lanRuntimeReadRunner{ip: map[string]string{}, firewall: map[string]string{}})
	calls := 0
	r.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error {
		calls++
		if calls == 2 {
			return ErrReviewChanged
		}
		return nil
	}
	err := r.Preflight(context.Background(), lanRuntimeFixture(t))
	if !errors.Is(err, ErrReviewChanged) || LANPolicyPreflightFailureStage(err) != "scope-close" || calls != 2 {
		t.Fatal("closing check lost", calls, err)
	}
	if LANPolicyPreflightFailureStage(&lanPolicyPreflightFailure{stage: "private unknown label", cause: ErrLANPolicyRuntime}) != "" {
		t.Fatal("non-closed stage exposed")
	}
}
