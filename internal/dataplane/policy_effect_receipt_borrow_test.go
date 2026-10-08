package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Actual COMMON writer, parser and file ownership; native effects are the
// existing explicit kernel model. These tests grant no native NFQ/LAN proof.
func TestPolicyEffectBorrowReadsOriginalLockedWriterAndRevokesAfterApply(t *testing.T) {
	f := newPolicyEffectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var escaped context.Context
	var earlier policyEffectBorrowObservation
	var sawAbsent, sawIntent, sawAdded bool
	f.runtime.Guard = func(c context.Context, _ int) error {
		o, present, err := observeBorrowedPolicyEffects(c, f.plan, f.root)
		if err != nil || !present {
			t.Fatalf("actual writer borrow refused: %v %v", present, err)
		}
		defer o.close()
		escaped = c
		if o.absent {
			sawAbsent = true
			earlier = o
		} else {
			if len(o.states) != len(f.plan.Effects) || o.checksum == "" {
				t.Fatal("unbound receipt states")
			}
			if earlier.borrow != nil && earlier.current(c) == nil {
				t.Fatal("old absent observation survived real receipt publication")
			}
			for _, state := range o.states {
				sawIntent = sawIntent || state == "intent"
				sawAdded = sawAdded || state == "added"
			}
		}
		if err := o.current(c); err != nil {
			t.Fatal("same original receipt changed during readonly observation", err)
		}
		if _, err := inspectPolicyEffects(c, f.plan, f.root, f.options); !errors.Is(err, ErrPolicyAdditionBusy) {
			t.Fatal("independent reader acquired original writer lock", err)
		}
		return nil
	}
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal(err)
	}
	if !sawAbsent || !sawIntent || !sawAdded || len(f.calls) != len(f.plan.Effects) {
		t.Fatal("actual phase/effect coverage missing", sawAbsent, sawIntent, sawAdded, len(f.calls))
	}
	if o, present, err := observeBorrowedPolicyEffects(escaped, f.plan, f.root); !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
		o.close()
		t.Fatal("released writer context revived", present, err)
	}
	if _, present, err := observeBorrowedPolicyEffects(ctx, f.plan, f.root); present || err != nil {
		t.Fatal("detached plan/context manufactured original writer", present, err)
	}
	status, err := inspectPolicyEffects(ctx, f.plan, f.root, f.options)
	if err != nil || !status.Complete {
		t.Fatal("borrow changed ordinary completed receipt", status, err)
	}
}

func TestPolicyEffectBorrowRefusesForeignPlanRootAndCopiedIssuer(t *testing.T) {
	f := newPolicyEffectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.runtime.Guard = func(c context.Context, _ int) error {
		wrongType := context.WithValue(c, policyEffectReceiptBorrowKey{}, true)
		if o, present, err := observeBorrowedPolicyEffects(wrongType, f.plan, f.root); !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
			o.close()
			t.Fatal("present wrong-type issuer fell through as absence", present, err)
		}
		wrong, _, _ := copyPolicyEffectPlan(f.plan)
		wrong.Effects[0].Add[0] = "-6"
		for _, input := range []struct {
			plan PolicyEffectPlan
			root string
		}{{wrong, f.root}, {f.plan, filepath.Join(f.root, "foreign")}} {
			if o, present, err := observeBorrowedPolicyEffects(c, input.plan, input.root); !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
				o.close()
				t.Fatal("foreign comparison acquired borrower", present, err)
			}
		}
		original := c.Value(policyEffectReceiptBorrowKey{}).(*policyEffectReceiptBorrow)
		copy := &policyEffectReceiptBorrow{self: original.self, session: original.session, anchor: original.anchor, marker: original.marker, markerInfo: original.markerInfo, open: true, absent: true}
		foreign := context.WithValue(c, policyEffectReceiptBorrowKey{}, copy)
		if o, present, err := observeBorrowedPolicyEffects(foreign, f.plan, f.root); !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
			o.close()
			t.Fatal("copied issuer acquired writer observation", present, err)
		}
		return nil
	}
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyEffectBorrowRefusesForgedAddedReceiptBeforeRPC(t *testing.T) {
	f := newPolicyEffectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var escaped context.Context
	f.runtime.Guard = func(c context.Context, _ int) error {
		o, present, err := observeBorrowedPolicyEffects(c, f.plan, f.root)
		if err != nil || !present {
			return errors.Join(ErrPolicyAdditionReceipt, err)
		}
		defer o.close()
		if o.absent || o.status.Pending == 0 {
			return nil
		}
		escaped = c
		data, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
		if err != nil {
			t.Fatal(err)
		}
		var forged policyAdditionDocument
		if json.Unmarshal(data, &forged) != nil {
			t.Fatal("invalid fixture receipt")
		}
		forged.Steps[0].State = "added"
		forged.Checksum = policyAdditionChecksum(forged)
		data, _ = json.Marshal(forged)
		if err := os.WriteFile(filepath.Join(f.root, policyAdditionFile), data, 0600); err != nil {
			t.Fatal(err)
		}
		fake, present, err := observeBorrowedPolicyEffects(c, f.plan, f.root)
		fake.close()
		if !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
			t.Fatal("valid-looking receipt manufactured original ACK", present, err)
		}
		return err
	}
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); !errors.Is(err, ErrPolicyAdditionReceipt) || len(f.calls) != 0 {
		t.Fatal("forged ACK reached modeled RPC", err, f.calls)
	}
	if o, present, err := observeBorrowedPolicyEffects(escaped, f.plan, f.root); !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
		o.close()
		t.Fatal("failed writer still issued observations", present, err)
	}
}

func TestPolicyEffectBorrowSaveFailureAndLostACKNeverKeepWriterAlive(t *testing.T) {
	for _, fault := range []string{"first-save", "lost-rpc-ack"} {
		t.Run(fault, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var escaped context.Context
			f.runtime.Guard = func(c context.Context, _ int) error {
				escaped = c
				o, present, err := observeBorrowedPolicyEffects(c, f.plan, f.root)
				o.close()
				if !present {
					return ErrPolicyAdditionReceipt
				}
				return err
			}
			if fault == "first-save" {
				f.runtime.Preflight = func(context.Context) error { return os.Mkdir(filepath.Join(f.root, policyAdditionFile), 0700) }
			} else {
				f.lostAdd = 0
			}
			if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err == nil {
				t.Fatal("unknown/failing write was accepted")
			}
			if o, present, err := observeBorrowedPolicyEffects(escaped, f.plan, f.root); !present || !errors.Is(err, ErrPolicyAdditionReceipt) {
				o.close()
				t.Fatal("failed writer revived from escaped context", present, err)
			}
			if fault == "first-save" {
				if len(f.calls) != 0 {
					t.Fatal("failed initial save reached effect", f.calls)
				}
			} else {
				status, err := inspectPolicyEffects(ctx, f.plan, f.root, f.options)
				if err != nil || !status.Unknown || status.Pending != 1 || status.Complete || len(f.calls) != 1 {
					t.Fatal("lost actual modeled ACK was converted to a completed receipt", status, err, f.calls)
				}
			}
		})
	}
}
