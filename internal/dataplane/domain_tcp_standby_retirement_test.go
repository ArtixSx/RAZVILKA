package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual COMMON writer/borrow protocol, with explicitly modeled packet effects.
// These fixtures do not construct native standby retirement authority.
func TestDomainTCPStandbyRemoveBindsOriginalLoadedReceiptBeforeAnyDelete(t *testing.T) {
	for _, change := range []string{"", "receipt-ABA", "copied-token", "closed-token"} {
		t.Run(change, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			ctx := context.Background()
			if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
				t.Fatal(err)
			}
			r := &domainTCPStandbyRetirement{owner: &domainTCPStandbyOwner{baseline: &syntheticBaselineExecutionResource{root: f.root}}}
			r.self = r
			r.open.Store(true)
			var err error
			r.receipt, err = observeNetworkPolicyEffects(ctx, f.plan, f.root, f.options)
			if err != nil {
				t.Fatal(err)
			}
			defer r.receipt.close()
			before := len(f.calls)
			switch change {
			case "receipt-ABA":
				raw, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
				if err != nil {
					t.Fatal(err)
				}
				if err := r.receipt.owner.WriteAtomic(policyAdditionFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "copied-token":
				r = &domainTCPStandbyRetirement{self: r, owner: r.owner}
			case "closed-token":
				r.open.Store(false)
			}
			ctx = context.WithValue(ctx, domainTCPStandbyRetirementKey{}, r)
			err = removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options)
			if change == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || len(f.calls) != before {
				t.Fatal("foreign receipt/token admitted deletion", err, len(f.calls), before)
			}
		})
	}
}

// Actual retained publication/descriptor protocol only. cleaned is an explicit
// model input here, never a source of production packet cleanup authority.
func standbyRetirementPublicationModel(t *testing.T) (*domainTCPStandbyRetirement, *retainedXrayExecution, context.Context) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-original")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	execution := &Execution{PlanID: "dp-check-" + strings.Repeat("a", 32), ResourcePlanID: "dp-" + strings.Repeat("a", 16), Digest: strings.Repeat("a", 64), State: "resource-failed"}
	transaction := filepath.Join(root, "transactions", execution.PlanID)
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	m := &Manager{StateRoot: root}
	s := &executionResourceScope{manager: m, managerRoot: root, root: transaction, execution: execution, open: true, ctx: ctx, cancel: cancel, retained: true}
	var err error
	s.owned, s.anchor, err = openNetworkPolicyObservationRoot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.owned.Close() })
	d := &xraySelectedTCPExecutionRecords{scope: s}
	d.root, d.anchor, err = openNetworkPolicyObservationRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	d.transactionRoot, d.transactionAnchor, err = openNetworkPolicyObservationRoot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.close() })
	p := &XrayDomainTCPExecutionResource{scope: s, records: d}
	p.self = p
	s.xrayDomainTCP = map[string]*XrayDomainTCPExecutionResource{"original": p}
	if err := m.writeExecutionOwned(transaction, *execution, s); err != nil {
		t.Fatal(err)
	}
	original := &DomainTCPOriginalScope{}
	original.self = original
	owner := &domainTCPStandbyOwner{process: p, original: original, baseline: &syntheticBaselineExecutionResource{relative: "execution-resources/sb-model"}}
	owner.self = owner
	original.standbyOwner = owner
	if err := d.detachStandbyAlias(ctx, owner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.latest.Close() })
	retained := &retainedXrayExecution{scope: s, records: d, standby: owner, pending: true}
	retained.self = retained
	s.retainedXrayOwner, m.retainedXray = retained, retained
	r := &domainTCPStandbyRetirement{owner: owner, cleaned: true}
	r.self = r
	original.standbyRetirement = r
	return r, retained, ctx
}

func TestDomainTCPStandbyFinalizationRetryKeepsOriginalCustody(t *testing.T) {
	for _, kind := range []string{"partial-publication", "before-close", "actual-close-error"} {
		t.Run(kind, func(t *testing.T) {
			r, retained, ctx := standbyRetirementPublicationModel(t)
			witness := errors.New("original finalization fault")
			once := false
			switch kind {
			case "partial-publication":
				r.publishFault = func(i int) error {
					if i == 1 && !once {
						once = true
						return witness
					}
					return nil
				}
			case "before-close":
				r.closeFault = func(i int) error {
					if i == 5 && !once {
						once = true
						return witness
					}
					return nil
				}
			case "actual-close-error":
				r.closeFault = func(i int) error {
					if i == 5 && !once {
						once = true
						return r.owner.latest.Close()
					}
					return nil
				}
			}
			err := r.publishRemoved(ctx, retained)
			if err == nil {
				t.Fatal("fault masked")
			}
			s := retained.scope
			if !s.retained || s.retainedXrayOwner != retained || s.manager.retainedXrayOwner() != retained || r.owner.original.standbyOwner != r.owner {
				t.Fatal("failed finalization lost original custody")
			}
			if kind == "actual-close-error" {
				if r.closeErr == nil {
					t.Fatal("fixture did not reach original close error", err)
				}
				if err := r.publishRemoved(ctx, retained); err == nil {
					t.Fatal("uncertain original FD adopted on retry")
				}
				return
			}
			if !errors.Is(err, witness) {
				t.Fatal("original exception lost", err)
			}
			if err := r.publishRemoved(ctx, retained); err != nil {
				t.Fatal("same original finalization did not resume", err)
			}
			if !r.finished || s.open || s.retained || s.manager.retainedXrayOwner() != nil || r.owner.original.standbyOwner != nil {
				t.Fatal("completed finalization retained active custody")
			}
		})
	}
}
