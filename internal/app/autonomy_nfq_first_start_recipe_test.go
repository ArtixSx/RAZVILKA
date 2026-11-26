package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/testlab"
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
			return dataplane.ErrNFQWSFirstStartScope
		}
		return nil
	}
	result := runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil)
	if result.State != "apply-refused" || !reflect.DeepEqual(a.Store.Get(), before) || len(model.recipes) != 1 || model.recipes[0] != before.NFQWSFirstStartRecipe || !slices.Contains(model.calls, "rollback") || slices.Contains(model.calls, "commit") || *probes != 0 {
		t.Fatal("health failure consumed recipe or bypassed rollback", result.State)
	}
	if len(result.Switches) != 1 || strings.Contains(result.Message, "штатную IP-политику") {
		t.Fatal("post-activation refusal treated as read-only preflight", result)
	}
	status, err := a.Dataplane.Status()
	if err != nil || status.Execution == nil || status.Execution.State != "rolled-back" || !status.Execution.RollbackVerified {
		t.Fatal("real Manager did not complete modeled compensation", err)
	}
}

func TestAutonomyStockFirstApplySchedulesScopedQueueConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, wantState string
		recipe          engineconfig.NFQWSFirstStartRecipe
		attributed      bool
	}{
		{name: "fixed-queue-proof", attributed: true, wantState: "healthy"},
		{name: "adaptive-queue-proof", recipe: engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto, attributed: true, wantState: "healthy"},
		{name: "unattributed-https-success", recipe: engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto, wantState: "unconfirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, model, probes := autoRecipeFixture(t)
			if err := a.Store.SetNFQWSFirstStartRecipe(a.Store.Get().Revision, tc.recipe); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"youtube", "speedtest"} {
				a.autonomyRuntime(a.autonomyPolicy().Revision, id, autonomy.Runtime{State: "healthy", NextCheck: time.Now().Add(time.Hour)})
			}
			first := runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil)
			if first.State != "applied" || !first.CheckedAt.IsZero() || *probes != 0 || !strings.Contains(first.Message, "Автопилот проверит HTTPS") {
				t.Fatal("transaction Health was treated as service proof", first, *probes)
			}
			before := a.Store.Get()
			calls := slices.Clone(model.calls)
			a.autonomyRuntime(a.autonomyPolicy().Revision, "discord", first)
			now := time.Now()
			due := a.nextAutonomySearchCheck(now)
			if !due.Equal(now.Add(reconcilerPollInterval)) {
				t.Fatal("early wake did not keep the ordinary lower bound", due, now, first.NextCheck)
			}
			var observations atomic.Int32
			a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, service catalog.Service, route string) testlab.Result {
				observations.Add(1)
				if service.ID != "discord" || route != "nfqws2" || !model.active || !model.committed {
					t.Error("confirmation did not observe the originally committed route", service.ID, route)
					return testlab.Result{}
				}
				result := confirmedRouteProber{}.Probe(ctx, service, route)
				if !tc.attributed {
					result.RouteConfirmed = false
					result.RouteProofError = "nfq-socket-unobserved"
				}
				return result
			})

			a.autonomyRound(context.Background(), due)
			a.autonomy.mu.Lock()
			confirmed := a.autonomy.doc.Runtime["discord"].Clone()
			a.autonomy.mu.Unlock()
			if observations.Load() != 1 || confirmed.State != tc.wantState || confirmed.CheckedAt.IsZero() || confirmed.Failures != 0 ||
				!slices.Equal(confirmed.Switches, first.Switches) || !reflect.DeepEqual(a.Store.Get(), before) || !slices.Equal(calls, model.calls) {
				t.Fatal("confirmation changed the assignment or misclassified HTTPS", confirmed, model.calls, observations.Load())
			}
			if next := a.nextAutonomySearchCheck(due); !next.IsZero() || !confirmed.NextCheck.Equal(due.Add(time.Duration(a.autonomyPolicy().CheckSeconds)*time.Second)) {
				t.Fatal("confirmation kept an early wake after its first observation", next, confirmed.NextCheck)
			}
		})
	}
}

func TestAutonomyStockConfirmationWakeRejectsNewDraftAndStop(t *testing.T) {
	for _, change := range []string{"edited-draft", "stopped"} {
		t.Run(change, func(t *testing.T) {
			a, model, probes := autoRecipeFixture(t)
			for _, id := range []string{"youtube", "speedtest"} {
				a.autonomyRuntime(a.autonomyPolicy().Revision, id, autonomy.Runtime{State: "healthy", NextCheck: time.Now().Add(time.Hour)})
			}
			a.autonomyRuntime(a.autonomyPolicy().Revision, "discord", runAutoNFQDispatcher(t, a, "discord", func() bool { return true }, nil))
			now := time.Now()
			if next := a.nextAutonomySearchCheck(now); next.IsZero() {
				t.Fatal("first Apply did not schedule confirmation")
			}
			if change == "edited-draft" {
				if err := a.Store.UpdateService("discord", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"discord": "nfqws2"}, a.Store.Get().Revision); err != nil {
				t.Fatal(err)
			}
			before := a.Store.Get()
			calls := slices.Clone(model.calls)
			if next := a.nextAutonomySearchCheck(now); !next.IsZero() {
				t.Fatal("stale stock confirmation expedited the queue", next)
			}
			a.autonomyRound(context.Background(), now.Add(reconcilerPollInterval))
			if *probes != 0 || !reflect.DeepEqual(a.Store.Get(), before) || !slices.Equal(calls, model.calls) {
				t.Fatal("stale stock confirmation reached the probe or an Apply", *probes, model.calls)
			}
		})
	}
}
