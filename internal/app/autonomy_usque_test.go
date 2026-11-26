package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type autonomyUSQUEApplyModel struct{ nodeApplyAdapter }

func (*autonomyUSQUEApplyModel) ID() string { return "usque" }

func setAutonomyUSQUEPolicy(t *testing.T, a *App, allowed bool) autonomy.Service {
	t.Helper()
	const id = "my-independent-site"
	for i := range a.Catalog.Services {
		if a.Catalog.Services[i].ID == id {
			a.Catalog.Services[i].ProbeURL = "https://93.184.216.34/"
			a.Catalog.Services[i].Category = "Fixture"
			a.Catalog.Services[i].Strategy = []string{"usque"}
		}
	}
	service, _ := a.autonomyService(id)
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	s := a.autonomy.doc.Services[id]
	s.Definition = autonomyDefinition(service)
	a.autonomy.doc.Services[id] = s
	a.autonomy.doc.Policy.PreferredRoutes = []string{"usque", "sing-box"}
	a.autonomy.doc.Policy.AllowInitialMASQUERegistration = allowed
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAutonomyUSQUEPreparedSessionUsesOnlyOwnDraftAndCommonTransaction(t *testing.T) {
	for _, scenario := range []string{"apply", "saved-session", "saved-shadowed", "canary-unproven", "canary-cleanup-failed", "canary-journal-failed", "editor-changed", "unowned-live", "targets-missing"} {
		t.Run(scenario, func(t *testing.T) {
			a, _, _ := autonomousIntegrationFixture(t)
			useSaved := scenario == "saved-session" || scenario == "saved-shadowed"
			s := setAutonomyUSQUEPolicy(t, a, !useSaved)
			p := a.autonomyPolicy()
			service, _ := a.autonomyService(s.ID)
			root := t.TempDir()
			configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
			configs.LiveRoot = filepath.Join(root, "live")
			a.EngineConfigs = configs
			staged, err := configs.Stage("usque", "main", `{"fixture":"scoped-session"}`)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := configs.Stage("sing-box", "main", `{"fixture":"unrelated-editor-draft"}`); err != nil {
				t.Fatal(err)
			}
			options := a.nodeReviews.options
			a.nodeReviews.options = func() []routecatalog.Option {
				return append(options(), routecatalog.Option{ID: "usque", Installed: true})
			}
			model := &autonomyUSQUEApplyModel{}
			model.after = func(stage string) error {
				if stage == "canary" && scenario == "canary-unproven" {
					return errors.New("isolated fixture did not reach service")
				}
				if stage == "canary" && scenario == "canary-cleanup-failed" {
					return dataplane.ErrOriginalProcessCleanup
				}
				if stage == "canary" && scenario == "canary-journal-failed" {
					return errors.Join(errors.New("isolated fixture did not reach service"), dataplane.ErrExecutionJournal)
				}
				if stage != "commit" {
					return nil
				}
				prepared, err := configs.ReadExpert("usque", "main")
				if useSaved {
					if err != nil || prepared.Source != "live" || prepared.SHA256 != staged.SHA256 || len(model.planned.EngineDrafts) != 0 {
						return errors.New("saved MASQUE session was rewritten or treated as a draft")
					}
					return nil
				}
				if err != nil || prepared.Source != "staged" || !slices.Equal(model.planned.EngineDrafts, []string{"usque/main"}) {
					return errors.New("exact MASQUE draft lost")
				}
				if err := os.MkdirAll(filepath.Dir(prepared.Path), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(prepared.Path, []byte(prepared.Content), 0o600); err != nil {
					return err
				}
				return configs.Discard("usque", "main")
			}
			if err := a.Dataplane.Register(model); err != nil {
				t.Fatal(err)
			}
			base := filepath.Dir(a.Dataplane.StateRoot)
			a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: filepath.Join(base, "control")}
			if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), a.SelfUpdateFiles.ControlRoot); err != nil {
				t.Fatal(err)
			}
			if err := a.ConfigureDefaultConsent(filepath.Join(base, "config.json"), filepath.Join(base, "nodes")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.CloseDefaultConsent() })
			ctx, release, err := a.scopedRuntimeOperation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			profile, err := a.freshNetworkProfile(ctx)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := a.defaultConsentOwner(ctx)
			if err != nil {
				t.Fatal(err)
			}
			targets, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, a.Store.Get(), a.catalogSnapshot(), s.ID)
			if err != nil {
				t.Fatal(err)
			}
			candidate := &autonomyUSQUECandidate{owner: a, configs: configs, service: service, network: profile,
				sources: slices.Clone(s.Sources), sha256: staged.SHA256, targets: targets, current: func(context.Context) error { return nil }}
			if scenario == "targets-missing" {
				candidate.targets = nil
			}
			if scenario == "editor-changed" {
				if _, err := configs.Stage("usque", "main", `{"fixture":"different-session"}`); err != nil {
					t.Fatal(err)
				}
			}
			if useSaved || scenario == "unowned-live" {
				view, err := configs.ReadExpert("usque", "main")
				if err != nil || os.MkdirAll(filepath.Dir(view.Path), 0o700) != nil || os.WriteFile(view.Path, []byte(view.Content), 0o600) != nil || configs.Discard("usque", "main") != nil {
					t.Fatal("unable to prepare unexpected live image", err)
				}
				if useSaved {
					candidate.livePath = view.Path
				}
			}
			if scenario == "saved-shadowed" {
				// A byte-identical editor draft still does not grant authority
				// to change which source the ongoing transaction consumes.
				if _, err := configs.Stage("usque", "main", staged.Content); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "apply" || scenario == "saved-session" {
				hypothetical := nodeRouteConfigForScope(a.Store.Get(), s.ID, "unused", s.Sources)
				state := hypothetical.Services[s.ID]
				state.Mode, state.Route = "usque", "usque"
				hypothetical.Services[s.ID] = state
				plan, err := a.buildPlanReprovingRetained(context.WithValue(ctx, autonomyUSQUECandidateKey{}, candidate), hypothetical, profile)
				if err != nil || !plan.Ready {
					t.Fatalf("MASQUE plan not ready: err=%v blockers=%+v", err, plan.Blockers)
				}
			}
			r, done := a.applyPreparedAutonomyUSQUE(ctx, p, s, autonomyTestState(a), a.Store.Get(), candidate)
			state := a.Store.Get().AppliedServices[s.ID]
			switch scenario {
			case "apply", "saved-session":
				if !done || r.State != "applied" || selectedRoute(state) != "usque" || !slices.Equal(state.Sources, s.Sources) ||
					!slices.Equal(model.calls, []string{"snapshot", "stage", "validate", "canary", "activate", "health", "commit"}) {
					t.Fatalf("prepared path bypassed the common transaction: %+v %v", r, model.calls)
				}
				if useSaved {
					current, err := configs.ReadExpert("usque", "main")
					if err != nil || current.Source != "live" || current.SHA256 != staged.SHA256 || p.AllowInitialMASQUERegistration {
						t.Fatal("reusing existing MASQUE required authorization or a config rewrite", err)
					}
				}
			case "canary-unproven", "canary-cleanup-failed", "canary-journal-failed":
				if !done || r.State != "requires-review" || state.Enabled || !slices.Contains(model.calls, "canary") || slices.Contains(model.calls, "activate") || len(r.Switches) != 1 || !a.Operations.Snapshot().Fenced {
					t.Fatalf("unproven canary cleanup authorized fallback or refunded its switch: %+v %v", r, model.calls)
				}
			case "editor-changed", "unowned-live", "saved-shadowed":
				if done || state.Enabled || len(model.calls) != 0 || len(r.Switches) != 0 {
					t.Fatalf("changed draft reached the dataplane: %+v %v", r, model.calls)
				}
			case "targets-missing":
				if done || r.State != "masque-target-unavailable" || state.Enabled || len(model.calls) != 0 || len(r.Switches) != 0 || a.Operations.Snapshot().Fenced {
					t.Fatalf("missing target owner reached Apply or halted other methods: %+v %v", r, model.calls)
				}
			}
			unrelated, err := configs.ReadExpert("sing-box", "main")
			if err != nil || unrelated.Source != "staged" || unrelated.Content != `{"fixture":"unrelated-editor-draft"}` {
				t.Fatal("MASQUE transaction consumed another engine draft", err)
			}
		})
	}
}

func TestAutonomyUSQUEMissingInitialSourceContinuesVLESS(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		a, nodes, reserve := autonomousIntegrationFixture(t)
		s := setAutonomyUSQUEPolicy(t, a, allowed)
		a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
			return d10Result(req, "sing-box", true), nil
		})
		a.autonomyRound(context.Background(), time.Now())
		if state := a.Store.Get().AppliedServices[s.ID]; selectedRoute(state) != "sing-box:"+nodes[0] || !slices.Contains(reserve.calls, "health") {
			t.Fatalf("unavailable MASQUE prevented later VLESS under consent %t: %+v %v", allowed, state, reserve.calls)
		}
	}
}

func TestAutonomyUSQUEConsentIsSeparatePersistentAndOptionalForOldClients(t *testing.T) {
	a := autonomyAPIFixture(t)
	p := saveAutonomyFixturePolicy(t, a)
	if p.AllowInitialMASQUERegistration {
		t.Fatal("existing configuration enabled registration")
	}
	const service = "arbitrary-site"
	if err := a.inheritAutonomyService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	p = a.autonomyPolicy()
	a.autonomyRuntime(a.autonomyPolicy().Revision, service, autonomy.Runtime{State: "masque-consent-required", NextCheck: time.Now().Add(time.Hour)})
	a.reconciler.doc.Operations = []automationOperation{{Kind: "feeds", State: "running", NextRun: time.Now().Add(time.Hour)}}
	save := func(choice *bool, status int) {
		t.Helper()
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		if choice == nil {
			delete(wire, "allow_initial_masque_registration")
		} else if wire["allow_initial_masque_registration"], err = json.Marshal(*choice); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{
			"expected_revision": p.Revision, "policy": wire, "confirm": "SAVE_AUTONOMY",
		}))
		if w.Code != status {
			t.Fatalf("save registration consent: %d %s", w.Code, w.Body.String())
		}
		fresh := &App{Store: a.Store, Catalog: a.Catalog}
		if err := fresh.loadAutonomy(context.Background()); err != nil {
			t.Fatal(err)
		}
		p = fresh.autonomyPolicy()
	}
	allow, deny := true, false
	revision := p.Revision
	save(&allow, http.StatusBadRequest)
	if p.Revision != revision || p.AllowInitialMASQUERegistration {
		t.Fatal("explicit MASQUE consent without the method changed settings")
	}
	p.PreferredRoutes = append(p.PreferredRoutes, "usque")
	save(&allow, http.StatusOK)
	if !p.AllowInitialMASQUERegistration {
		t.Fatal("explicit MASQUE opt-in did not persist")
	}
	waiting := a.autonomy.doc.Runtime[service]
	if waiting.State != "pending" || !waiting.NextCheck.IsZero() || !a.reconciler.autonomyWakePending {
		t.Fatalf("new MASQUE consent was not delivered to the running queue: %+v", waiting)
	}
	a.reconciler.autonomyWakePending = false
	save(nil, http.StatusOK)
	if !p.AllowInitialMASQUERegistration || a.reconciler.autonomyWakePending {
		t.Fatal("old client omission changed MASQUE consent")
	}
	p.PreferredRoutes = slices.DeleteFunc(p.PreferredRoutes, func(route string) bool { return route == "usque" })
	save(nil, http.StatusOK)
	if p.AllowInitialMASQUERegistration {
		t.Fatal("old client removal did not revoke the associated registration consent")
	}
	p.PreferredRoutes = append(p.PreferredRoutes, "usque")
	save(nil, http.StatusOK)
	if p.AllowInitialMASQUERegistration {
		t.Fatal("old client re-add revived registration consent")
	}
	save(&allow, http.StatusOK)
	save(&deny, http.StatusOK)
	if p.AllowInitialMASQUERegistration {
		t.Fatal("explicit MASQUE revocation did not persist")
	}
}
