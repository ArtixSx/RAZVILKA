package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// The host/process/HTTP fixture remains modeled; the natural dispatcher, plan,
// Manager, closed stock recipe compiler, staged bytes and Store publication are
// real. This proves recipe propagation, not router packet or service success.
type autonomyRecipeStageModel struct {
	*nfqDefinitionRuntimeModel
	stock   []byte
	recipes []engineconfig.NFQWSFirstStartRecipe
}

const autonomyRecipeOwner = "0123456789abcdef01234567"

func (m *autonomyRecipeStageModel) Stage(ctx context.Context, plan dataplane.Plan, root string) error {
	m.recipes = append(m.recipes, plan.NFQWSFirstStartRecipe)
	var domains []string
	for _, route := range plan.Routes {
		if route.Resolved != "nfqws2" || len(route.CIDRs) != 0 || len(route.Sources) != 0 {
			return errors.New("fixture scope changed")
		}
		domains = append(domains, route.Domains...)
	}
	data, err := engineconfig.NFQWSFirstStartConfigForRecipe(m.stock, autonomyRecipeOwner, domains, nil, nil, plan.NFQWSFirstStartRecipe)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "nfqws2.conf.staged"), data, 0600); err != nil {
		return err
	}
	return m.nfqDefinitionRuntimeModel.Stage(ctx, plan, root)
}
func (m *autonomyRecipeStageModel) Validate(ctx context.Context, plan dataplane.Plan, root string) error {
	data, err := os.ReadFile(filepath.Join(root, "nfqws2.conf.staged"))
	if err != nil {
		return err
	}
	recipe, err := engineconfig.NFQWSFirstStartConfigRecipe(data, autonomyRecipeOwner)
	if err != nil || recipe != plan.NFQWSFirstStartRecipe {
		return errors.New("staged recipe differs from candidate")
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(data, autonomyRecipeOwner)
	if err != nil {
		return err
	}
	if recipe == engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto && (!strings.Contains(string(effective), "--fastpath-workaround=auto") || !strings.Contains(string(data), "# RAZVILKA RECIPE "+string(recipe))) {
		return errors.New("selected closed recipe was not staged")
	}
	return m.nfqDefinitionRuntimeModel.Validate(ctx, plan, root)
}
func (m *autonomyRecipeStageModel) VerifyRollback(ctx context.Context, _ dataplane.Plan, _ string) (bool, error) {
	return !m.active && ctx.Err() == nil, ctx.Err()
}

func autoRecipeFixture(t *testing.T) (*App, *autonomyRecipeStageModel, *int) {
	t.Helper()
	a, model, probes := autoNFQFirstStartFixture(t)
	stock, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	stager := &autonomyRecipeStageModel{nfqDefinitionRuntimeModel: model, stock: stock}
	a.Dataplane = dataplane.New(filepath.Join(t.TempDir(), "recipe-dataplane"))
	a.Dataplane.FreshProfile = stableNodeProfile
	if err := a.Dataplane.Register(stager); err != nil {
		t.Fatal(err)
	}
	return a, stager, probes
}

func TestAutonomyNaturalNFQFirstStartStagesAndPublishesSelectedRecipe(t *testing.T) {
	for _, recipe := range []engineconfig.NFQWSFirstStartRecipe{"", engineconfig.NFQWSFirstStartStockTLSCircular, engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto} {
		t.Run(string(recipe), func(t *testing.T) {
			a, model, probes := autoRecipeFixture(t)
			if err := a.Store.SetNFQWSFirstStartRecipe(a.Store.Get().Revision, recipe); err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			result := runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil)
			plan, ok, err := a.Dataplane.Committed()
			if err != nil || !ok || result.State != "applied" || len(model.recipes) != 1 || model.recipes[0] != recipe || plan.NFQWSFirstStartRecipe != recipe || *probes != 0 {
				t.Fatal("natural first-start lost selected recipe or required pre-PASS", result.State, model.recipes, plan.NFQWSFirstStartRecipe, model.calls, err)
			}
			after := a.Store.Get()
			if after.Revision != before.Revision+1 || after.NFQWSFirstStartRecipe != recipe || after.AppliedNFQWSFirstStartRecipe != recipe || len(after.AppliedServices) != 1 || after.AppliedServices["discord"].Route != "nfqws2" {
				t.Fatal("recipe and route were not one publication")
			}
			for id, state := range before.Services {
				if id != "discord" && !reflect.DeepEqual(after.Services[id], state) {
					t.Fatal("unrelated pending service changed", id)
				}
			}
			// Adding another service must retain the applied global recipe, not
			// silently consume the user's next pending recipe edit.
			pending := engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto
			if recipe == pending {
				pending = engineconfig.NFQWSFirstStartStockTLSCircular
			}
			if err := a.Store.SetNFQWSFirstStartRecipe(after.Revision, pending); err != nil {
				t.Fatal(err)
			}
			result = runAutoNFQDispatcher(t, a, "youtube", func() bool { return true }, nil)
			plan, ok, err = a.Dataplane.Committed()
			if err != nil || !ok || result.State != "applied" || len(model.recipes) != 2 || model.recipes[1] != recipe || plan.NFQWSFirstStartRecipe != recipe || a.Store.Get().AppliedNFQWSFirstStartRecipe != recipe || a.Store.Get().NFQWSFirstStartRecipe != pending {
				t.Fatal("retained NFQ profile consumed pending recipe", result.State, err)
			}
		})
	}
}

func TestAutonomyNaturalNFQFirstStartHealthRefusalPreservesDesiredRecipe(t *testing.T) {
	a, model, probes := autoRecipeFixture(t)
	if err := a.Store.SetNFQWSFirstStartRecipe(a.Store.Get().Revision, engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	model.after = func(phase string) error {
		if phase == "health" {
			return errors.New("modeled TLS refusal")
		}
		return nil
	}
	result := runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil)
	if result.State != "apply-refused" || !reflect.DeepEqual(a.Store.Get(), before) || len(model.recipes) != 1 || model.recipes[0] != before.NFQWSFirstStartRecipe || !slices.Contains(model.calls, "rollback") || slices.Contains(model.calls, "commit") || *probes != 0 {
		t.Fatal("health failure consumed recipe or bypassed rollback", result.State)
	}
	status, err := a.Dataplane.Status()
	if err != nil || status.Execution == nil || status.Execution.State != "rolled-back" || !status.Execution.RollbackVerified {
		t.Fatal("real Manager did not complete modeled compensation", err)
	}
}
