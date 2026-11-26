package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func lanDirectReceiptFixture(t *testing.T) (*LANPolicyReceiptBinding, *lanPolicyReceiptModel, string) {
	t.Helper()
	b, model, root := lanReceiptBindingFixture(t)
	plan, err := CompileNFQWSDirectLANPolicyRuntime(model.plan.Generation, model.plan.Ingress)
	if err != nil {
		t.Fatal(err)
	}
	model.plan = plan
	guard := func(ctx context.Context, got *LANPolicyRuntimePlan, _ LANPolicyEffect) error {
		if !reflect.DeepEqual(got, plan) {
			return ErrReviewChanged
		}
		return ctx.Err()
	}
	b.ApplyGuard, b.CleanupGuard = guard, guard
	return b, model, root
}

// Real anchored COMMON roots, locks, canonical records and promotion protocol;
// physical/kernel leaves are explicit models. No process or packet is started.
func TestLANDirectPreparationPromotesOneOwnerAndRequiresFreshSettlement(t *testing.T) {
	b, model, source := lanDirectReceiptFixture(t)
	ctx := context.Background()
	if err := b.Apply(ctx, model.plan, source); err != nil {
		t.Fatal(err)
	}
	first, err := b.Inspect(ctx, model.plan, source)
	if err != nil || !first.Complete || first.Removed || first.Added != 0 || len(model.calls) != 0 {
		t.Fatal("preparation claimed a kernel effect", first, err)
	}
	if err := b.Apply(ctx, model.plan, source); !errors.Is(err, ErrPolicyAdditionExists) {
		t.Fatal("preparation replay adopted original record", err)
	}
	if _, err := inspectPolicyEffects(ctx, PolicyEffectPlan{Generation: model.plan.Generation}, source, b.options); err == nil {
		t.Fatal("ordinary empty effect reader adopted no-effect record")
	}
	destination := privateScopedXrayFixtureDir(t)
	if err := b.Promote(ctx, model.plan, source, destination); err != nil {
		t.Fatal(err)
	}
	old, err := b.Inspect(ctx, model.plan, source)
	current, currentErr := b.Inspect(ctx, model.plan, destination)
	if err != nil || currentErr != nil || !old.Promoted || old.Complete || !current.Complete || old.ID != first.ID || current.ID != first.ID {
		t.Fatal("original record did not transfer once", old, current, err, currentErr)
	}
	if err := b.Remove(ctx, model.plan, source); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("retired source recovered cleanup authority", err)
	}
	blocked := errors.New("modeled unsettled actual consumer")
	b.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error { return blocked }
	if err := b.Remove(ctx, model.plan, destination); !errors.Is(err, blocked) {
		t.Fatal("record removal skipped fresh consumer settlement", err)
	}
	still, err := b.Inspect(ctx, model.plan, destination)
	if err != nil || still != current {
		t.Fatal("failed settlement changed prepared owner", still, err)
	}
	b.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error { return nil }
	b.ApplyGuard = func(context.Context, *LANPolicyRuntimePlan, LANPolicyEffect) error { return ErrReviewChanged }
	b.Runtime.ScopeCheck = func(context.Context, *LANPolicyRuntimePlan) error { return ErrReviewChanged }
	if err := b.Remove(ctx, model.plan, destination); err != nil {
		t.Fatal("known cleanup borrowed expired apply review", err)
	}
	removed, err := b.Inspect(ctx, model.plan, destination)
	if err != nil || !removed.Removed || removed.Complete || removed.Unknown || len(model.calls) != 0 {
		t.Fatal("cleanup falsely claimed an effect", removed, err)
	}
}

func TestLANDirectPreparationChangedRootPlanBootAndPromotionCrashRefuse(t *testing.T) {
	for _, failure := range []string{"copy-root", "plan", "boot", "promotion-intent", "promotion-copy"} {
		t.Run(failure, func(t *testing.T) {
			b, model, source := lanDirectReceiptFixture(t)
			ctx := context.Background()
			if err := b.Apply(ctx, model.plan, source); err != nil {
				t.Fatal(err)
			}
			destination := privateScopedXrayFixtureDir(t)
			switch failure {
			case "copy-root":
				data, err := os.ReadFile(filepath.Join(source, policyAdditionFile))
				if err != nil || os.WriteFile(filepath.Join(destination, policyAdditionFile), data, 0600) != nil {
					t.Fatal(err)
				}
				if _, err := b.Inspect(ctx, model.plan, destination); err == nil {
					t.Fatal("copied preparation acquired another root")
				}
			case "plan":
				changed, err := CompileNFQWSDirectLANPolicyRuntime(model.plan.Generation, append([]LANPolicyIngress(nil), model.plan.Ingress...))
				if err != nil {
					t.Fatal(err)
				}
				changed.Ingress[0].ExcludedMACs = append(changed.Ingress[0].ExcludedMACs, "02:AA:BB:CC:DD:EE")
				changed.Digest = lanPolicyDigest(changed)
				if _, err := b.Inspect(ctx, changed, source); err == nil {
					t.Fatal("changed immutable scope adopted old preparation")
				}
			case "boot":
				b.options.boot = func() (string, error) { return "different-actual-model-boot", nil }
				if _, err := b.Inspect(ctx, model.plan, source); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("another boot adopted original preparation", err)
				}
			default:
				b.options.fault = func(stage string, _ int) error {
					if stage == failure {
						return ErrPolicyAdditionUnknown
					}
					return nil
				}
				if err := b.Promote(ctx, model.plan, source, destination); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("promotion failure was lost", err)
				}
				status, err := b.Inspect(ctx, model.plan, source)
				if err != nil || !status.Unknown || status.Complete || status.Removed {
					t.Fatal("unknown transfer became prepared or retired", status, err)
				}
				b.options.fault = nil
				if err := b.Promote(ctx, model.plan, source, destination); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("unknown transfer replayed", err)
				}
			}
			if len(model.calls) != 0 {
				t.Fatal("metadata fault executed a kernel command")
			}
		})
	}
}
