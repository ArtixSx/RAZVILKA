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
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// nfqws2HookModel stands in for the two Manager entry points. The default
// restoration succeeds for IPv4 under the observed instance.
type nfqws2HookModel struct {
	class      string
	instance   string
	observeErr error
	observed   int
	restored   int
	observe    func(context.Context, dataplane.Plan)
	restore    func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error)
}

func nfqws2HookAppFixture(t *testing.T) (*App, dataplane.Plan, *nfqws2HookModel) {
	t.Helper()
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, FreshProfile: stableNodeProfile, Dataplane: dataplane.New(filepath.Join(root, "dataplane")), Audit: auditlog.New(filepath.Join(root, "audit.log"))}
	a.Dataplane.FreshProfile = stableNodeProfile
	a.EngineConfigs = engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	if _, err := a.EngineConfigs.Stage("nfqws2", "user-list", "unapplied.example\n"); err != nil {
		t.Fatal(err)
	}
	// A registered non-NFQWS2 adapter keeps forwarding repair a no-op and
	// makes the real Manager refuse after the caller's review guard.
	if err := a.Dataplane.Register(&serviceRuntimeAdapter{nodeApplyAdapter: &nodeApplyAdapter{}, name: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-nfqws2-hooks", Digest: strings.Repeat("d", 64), Revision: store.Get().AppliedRevision, State: "committed", Ready: true,
		Adapters: []string{"nfqws2"}, Routes: []dataplane.Route{{ServiceID: "youtube", Selected: "nfqws2", Resolved: "nfqws2"}}}
	if err := a.Dataplane.Record(plan); err != nil {
		t.Fatal(err)
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		t.Fatal("no committed fixture", err)
	}
	model := &nfqws2HookModel{class: dataplane.NFQWS2HooksLoss, instance: "instance-a"}
	a.nfqws2Hooks.observe = func(ctx context.Context, got dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		model.observed++
		if model.observe != nil {
			model.observe(ctx, got)
		}
		return dataplane.NFQWS2HookRestore{Class: model.class, Instance: model.instance}, model.observeErr
	}
	a.nfqws2Hooks.restore = func(ctx context.Context, got dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		model.restored++
		if model.restore != nil {
			return model.restore(ctx, got)
		}
		return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Restored: []int{4}, Instance: model.instance}, nil
	}
	return a, plan, model
}

func nfqws2HookFailure(reason string) func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
	return func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Reason: reason, RolledBack: true}, errors.Join(dataplane.ErrNFQWS2HookRestore, errors.New("modeled "+reason))
	}
}

func nfqws2HookAudits(t *testing.T, a *App) []string {
	t.Helper()
	var events []string
	for _, event := range a.Audit.Read(100).Events {
		if event.Action != "RESTORE" || event.Actor != "router" || event.RemoteIP != "local" {
			t.Fatalf("unexpected audit event %+v", event)
		}
		events = append(events, event.Outcome+" "+event.Path)
	}
	slices.Sort(events)
	return events
}

func TestNFQWS2HookRepairRestoresUnderExclusiveAdmission(t *testing.T) {
	a, plan, model := nfqws2HookAppFixture(t)
	before := a.Store.Get()
	draft, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
	if err != nil {
		t.Fatal(err)
	}
	model.observe = func(ctx context.Context, got dataplane.Plan) {
		// The cheap observation shares admission and never excludes readers.
		if release, err := a.Operations.Exclusive(ctx); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			t.Fatal("observation ran without shared admission", err)
		}
		release, err := a.Operations.Enter(ctx)
		if err != nil {
			t.Fatal("observation took exclusive admission", err)
		}
		release()
	}
	model.restore = func(ctx context.Context, got dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		if !reflect.DeepEqual(got, plan) {
			t.Fatal("a draft or another plan reached hook repair")
		}
		if release, err := a.Operations.Enter(ctx); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			t.Fatal("repair did not retain exclusive admission", err)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > nfqws2HookRoundTimeout {
			t.Fatal("unbounded hook repair")
		}
		if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			t.Fatal("repair context lost its original admission", err)
		}
		return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Restored: []int{4}, Instance: model.instance}, nil
	}
	if err := a.restoreNFQWS2HooksRound(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
	if err != nil || !reflect.DeepEqual(draft, after) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("hook repair changed configuration or a draft", err)
	}
	if model.observed != 1 || model.restored != 1 || !slices.Equal(nfqws2HookAudits(t, a), []string{"ok /runtime/nfqws2"}) {
		t.Fatal("restoration was not audited once", model, nfqws2HookAudits(t, a))
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("admission not released", err)
	}
	release()
	// A complete graph is a cheap no-op: no exclusive admission, no audit.
	model.class, model.observe = dataplane.NFQWS2HooksFull, nil
	if err := a.restoreNFQWS2HooksRound(context.Background(), time.Now()); err != nil || model.observed != 2 || model.restored != 1 || len(nfqws2HookAudits(t, a)) != 1 {
		t.Fatal("full graph reached repair", err, model)
	}
}

func TestNFQWS2HookRepairRefusesBeforeEffect(t *testing.T) {
	for _, mode := range []string{"safe", "stopped", "due-stop", "self-update-stop", "component-update", "busy", "shared-busy", "canceled", "fenced", "applied-revision", "lan-owner", "not-committed", "observe-refused"} {
		t.Run(mode, func(t *testing.T) {
			a, plan, model := nfqws2HookAppFixture(t)
			ctx := context.Background()
			switch mode {
			case "safe":
				if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				// The same live control store operation as the panel's Stop.
				cfg := a.Store.Get()
				if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"youtube": cfg.AppliedServices["youtube"].Route}, cfg.Revision); err != nil {
					t.Fatal(err)
				}
			case "due-stop":
				a.reconciler.started = true
				a.reconciler.doc.Jobs = []durableServiceJob{{ID: 1, Request: serviceControlJobRequest{Kind: "stop"}, State: "queued", CreatedAt: time.Now()}}
			case "self-update-stop":
				nfqws2HookSelfUpdateStop(t, a)
			case "component-update":
				// An unreadable update journal is a pending update (fail closed).
				a.Components = components.New()
				a.Components.StateDir = filepath.Join(t.TempDir(), "components")
				if err := os.MkdirAll(filepath.Join(a.Components.StateDir, "update-journal"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(a.Components.StateDir, "update-journal", "current.json"), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
				if !a.PendingComponentRecovery() {
					t.Fatal("fixture has no pending component update")
				}
			case "busy":
				release, err := a.Operations.Exclusive(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "shared-busy":
				release, err := a.Operations.Enter(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "fenced":
				a.Operations.FenceJournal()
			case "applied-revision":
				if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
					t.Fatal(err)
				}
				if err := a.Store.ApplyDraft(); err != nil {
					t.Fatal(err)
				}
			case "lan-owner":
				plan.LAN = &dataplane.LANPolicyRuntimePlan{}
				if err := a.Dataplane.Record(plan); err != nil {
					t.Fatal(err)
				}
			case "not-committed":
				plan.Ready = false
				if err := a.Dataplane.Record(plan); err != nil {
					t.Fatal(err)
				}
			case "observe-refused":
				model.observeErr = errors.Join(dataplane.ErrNFQWS2HookRestore, errors.New("modeled kernel read failure"))
			}
			before := a.Store.Get()
			draft, err := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
			if err != nil {
				t.Fatal(err)
			}
			err = a.restoreNFQWS2HooksRound(ctx, time.Now())
			wantObserved := map[string]int{"shared-busy": 1, "observe-refused": 1}[mode]
			if model.observed != wantObserved || model.restored != 0 {
				t.Fatalf("refused state reached the runtime: observed=%d restored=%d err=%v", model.observed, model.restored, err)
			}
			if mode == "observe-refused" && !errors.Is(err, dataplane.ErrNFQWS2HookRestore) {
				t.Fatal("observation refusal hidden", err)
			}
			after, readErr := a.EngineConfigs.ReadExpert("nfqws2", "user-list")
			if readErr != nil || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(draft, after) {
				t.Fatal("refused repair changed configuration or a draft")
			}
			if audits := nfqws2HookAudits(t, a); len(audits) != 0 {
				t.Fatal("a skipped repair was audited", audits)
			}
		})
	}
}

func nfqws2HookSelfUpdateStop(t *testing.T, a *App) {
	t.Helper()
	control := filepath.Join(t.TempDir(), "control")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal(err)
	}
	a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: control}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, control, strings.Repeat("c", 32), a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
}

// The review guard travels with the operation into the real Manager, which
// consults it before its first check; each change after admission refuses.
func TestNFQWS2HookRepairGuardRechecksAuthorityAfterAdmission(t *testing.T) {
	for _, mode := range []string{"none", "stopped", "safe", "applied-revision", "due-stop", "self-update-stop", "fenced", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			a, _, model := nfqws2HookAppFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var want error
			model.restore = func(c context.Context, got dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
				switch mode {
				case "stopped":
					cfg := a.Store.Get()
					if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"youtube": "nfqws2"}, cfg.Revision); err != nil {
						t.Fatal(err)
					}
					want = errNFQWS2HookAuthority
				case "safe":
					if err := a.Store.SetSafeMode(true); err != nil {
						t.Fatal(err)
					}
					want = errNFQWS2HookAuthority
				case "applied-revision":
					if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
						t.Fatal(err)
					}
					if err := a.Store.ApplyDraft(); err != nil {
						t.Fatal(err)
					}
					want = errNFQWS2HookAuthority
				case "due-stop":
					a.reconciler.mu.Lock()
					a.reconciler.started = true
					a.reconciler.doc.Jobs = []durableServiceJob{{ID: 1, Request: serviceControlJobRequest{Kind: "stop"}, State: "queued", CreatedAt: time.Now()}}
					a.reconciler.mu.Unlock()
					want = errNFQWS2HookAuthority
				case "self-update-stop":
					nfqws2HookSelfUpdateStop(t, a)
					want = operationgate.ErrSelfUpdateStopped
				case "fenced":
					a.Operations.FenceJournal()
					want = operationgate.ErrRecovery
				case "canceled":
					cancel()
					want = context.Canceled
				}
				return a.Dataplane.RestoreCommittedNFQWS2Hooks(c, got)
			}
			err := a.restoreNFQWS2HooksRound(ctx, time.Now())
			if model.restored != 1 || !errors.Is(err, dataplane.ErrNFQWS2HookRestore) {
				t.Fatal("fixture did not reach the real Manager", model.restored, err)
			}
			if mode == "none" {
				for _, refusal := range []error{errNFQWS2HookAuthority, operationgate.ErrSelfUpdateStopped, operationgate.ErrRecovery, context.Canceled} {
					if errors.Is(err, refusal) {
						t.Fatal("current authority was refused", err)
					}
				}
				return
			}
			if !errors.Is(err, want) {
				t.Fatalf("guard did not refuse %s: %v", mode, err)
			}
			if audits := nfqws2HookAudits(t, a); len(audits) != 0 {
				t.Fatal("superseded authority was audited as a failure", audits)
			}
		})
	}
}

func TestNFQWS2HookRepairBacksOffFailuresAndResetsOnSuccess(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonWrite)
	now := time.Now()
	at := now
	for i, delay := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute} {
		if err := a.restoreNFQWS2HooksRound(context.Background(), at); !errors.Is(err, dataplane.ErrNFQWS2HookRestore) || model.restored != i+1 {
			t.Fatalf("attempt %d not made: restored=%d err=%v", i+1, model.restored, err)
		}
		// Observation continues meanwhile; admission waits for the delay.
		if err := a.restoreNFQWS2HooksRound(context.Background(), at.Add(delay-time.Second)); err != nil || model.restored != i+1 {
			t.Fatalf("attempt %d retried before %v: restored=%d err=%v", i+1, delay, model.restored, err)
		}
		at = at.Add(delay)
	}
	if audits := nfqws2HookAudits(t, a); !slices.Equal(audits, []string{"failed /runtime/nfqws2/write-failed"}) {
		t.Fatal("repeated failure was not audited exactly once", audits)
	}
	model.restore = nil
	if err := a.restoreNFQWS2HooksRound(context.Background(), at); err != nil || model.restored != 9 {
		t.Fatal("success after backoff not made", err)
	}
	// Success resets the delay and the deduplication of the same failure.
	model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonWrite)
	at = at.Add(2 * time.Minute)
	for _, step := range []struct {
		after    time.Duration
		restored int
	}{{0, 10}, {29 * time.Second, 10}, {30 * time.Second, 11}} {
		_ = a.restoreNFQWS2HooksRound(context.Background(), at.Add(step.after))
		if model.restored != step.restored {
			t.Fatalf("delay after success was not reset at %v: restored=%d", step.after, model.restored)
		}
	}
	if audits := nfqws2HookAudits(t, a); !slices.Equal(audits, []string{"failed /runtime/nfqws2/write-failed", "failed /runtime/nfqws2/write-failed", "ok /runtime/nfqws2"}) {
		t.Fatal("audit after success", audits)
	}
}

func TestNFQWS2HookRepairRetriesRacingRewriteBeforeBackingOff(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonChanged)
	now := time.Now()
	for i, at := range []time.Duration{0, 30 * time.Second, time.Minute, 90 * time.Second, 150 * time.Second} {
		_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(at))
		if model.restored != i+1 {
			t.Fatalf("attempt %d at %v not made: restored=%d", i+1, at, model.restored)
		}
		audits := nfqws2HookAudits(t, a)
		if i < 2 && len(audits) != 0 || i >= 2 && !slices.Equal(audits, []string{"failed /runtime/nfqws2/kernel-changed"}) {
			t.Fatalf("racing rewrite audit after attempt %d: %v", i+1, audits)
		}
	}
	// The third consecutive race is a failure; later races keep growing.
	_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(150*time.Second+59*time.Second))
	if model.restored != 5 {
		t.Fatal("persistent race did not grow the delay", model.restored)
	}
}

func TestNFQWS2HookRepairUncertainCleanupRequiresReview(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	model.restore = func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksLoss, Reason: dataplane.NFQWS2HookReasonWrite, Uncertain: true, Instance: "instance-a"}, errors.Join(dataplane.ErrNFQWS2HookRestore, dataplane.ErrNFQWS2HookUncertain)
	}
	now := time.Now()
	for _, step := range []struct {
		after    time.Duration
		restored int
	}{{0, 1}, {time.Minute, 1}, {29 * time.Minute, 1}, {30 * time.Minute, 2}, {31 * time.Minute, 2}} {
		_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(step.after))
		if model.restored != step.restored {
			t.Fatalf("uncertain cleanup retried at %v: restored=%d", step.after, model.restored)
		}
	}
	if audits := nfqws2HookAudits(t, a); !slices.Equal(audits, []string{"failed /runtime/nfqws2/cleanup-uncertain"}) {
		t.Fatal("uncertain cleanup audit", audits)
	}
}

func TestNFQWS2HookRepairRepeatedQuickLossRequiresReview(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	now := time.Now()
	// Three restorations, each lost again within a minute; the third quick
	// loss is not restored but held for review at the slow pace.
	for _, step := range []struct {
		after    time.Duration
		restored int
	}{{0, 1}, {10 * time.Second, 2}, {20 * time.Second, 3}, {30 * time.Second, 3}, {40 * time.Second, 3}, {30*time.Minute + 29*time.Second, 3}, {30*time.Minute + 30*time.Second, 4}} {
		_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(step.after))
		if model.restored != step.restored {
			t.Fatalf("quick-loss limit at %v: restored=%d want %d", step.after, model.restored, step.restored)
		}
	}
	if audits := nfqws2HookAudits(t, a); !slices.Equal(audits, []string{"failed /runtime/nfqws2/repeated-loss", "ok /runtime/nfqws2", "ok /runtime/nfqws2", "ok /runtime/nfqws2", "ok /runtime/nfqws2"}) {
		t.Fatal("repeated loss audit", audits)
	}
	// After the review retry one more quick loss is held again at once,
	// while a loss after a full minute starts counting from zero.
	_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(30*time.Minute+40*time.Second))
	if model.restored != 4 {
		t.Fatal("quick loss after review retry was restored", model.restored)
	}
	b, _, slow := nfqws2HookAppFixture(t)
	for i, after := range []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute} {
		_ = b.restoreNFQWS2HooksRound(context.Background(), now.Add(after))
		if slow.restored != i+1 {
			t.Fatal("slow repeated loss was held for review", after, slow.restored)
		}
	}
}

func TestNFQWS2HookRepairNewInstanceStartsOver(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonQueue)
	now := time.Now()
	_ = a.restoreNFQWS2HooksRound(context.Background(), now)
	_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(time.Second))
	if model.restored != 1 {
		t.Fatal("failure did not back off", model.restored)
	}
	// A restarted stock process (or another transaction) is a new key.
	model.instance = "instance-b"
	_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(2*time.Second))
	if model.restored != 2 {
		t.Fatal("new instance inherited the old backoff", model.restored)
	}
	if audits := nfqws2HookAudits(t, a); !slices.Equal(audits, []string{"failed /runtime/nfqws2/queue-binding", "failed /runtime/nfqws2/queue-binding"}) {
		t.Fatal("refusal was not audited once per key", audits)
	}
}

func TestNFQWS2HookRepairSkipsBusyAndSupersededWithoutBackoff(t *testing.T) {
	for name, restore := range map[string]func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error){
		"busy": func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
			return dataplane.NFQWS2HookRestore{Reason: dataplane.NFQWS2HookReasonBusy}, errors.Join(dataplane.ErrNFQWS2HookRestore, dataplane.ErrNFQWS2HookBusy)
		},
		"guard":         nfqws2HookFailure(dataplane.NFQWS2HookReasonGuard),
		"plan-changed":  nfqws2HookFailure(dataplane.NFQWS2HookReasonPlan),
		"lease-stopped": nfqws2HookFailure(dataplane.NFQWS2HookReasonLease),
		"canceled": func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
			return dataplane.NFQWS2HookRestore{Reason: dataplane.NFQWS2HookReasonWrite, RolledBack: true}, errors.Join(dataplane.ErrNFQWS2HookRestore, context.Canceled)
		},
		"full-no-op": func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
			return dataplane.NFQWS2HookRestore{Class: dataplane.NFQWS2HooksFull}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, _, model := nfqws2HookAppFixture(t)
			model.restore = restore
			now := time.Now()
			_ = a.restoreNFQWS2HooksRound(context.Background(), now)
			_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(time.Second))
			if model.restored != 2 {
				t.Fatal("a skipped attempt delayed the next round", model.restored)
			}
			if audits := nfqws2HookAudits(t, a); len(audits) != 0 {
				t.Fatal("a skipped attempt was audited", audits)
			}
		})
	}
}

func TestNFQWS2HookRepairRefusedOtherGraphIsAuditedOnce(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	model.class = dataplane.NFQWS2HooksOther
	model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonOther)
	now := time.Now()
	for _, after := range []time.Duration{0, 30 * time.Second, 90 * time.Second} {
		_ = a.restoreNFQWS2HooksRound(context.Background(), now.Add(after))
	}
	if model.restored != 3 || !slices.Equal(nfqws2HookAudits(t, a), []string{"failed /runtime/nfqws2/kernel-other"}) {
		t.Fatal("foreign graph refusal", model.restored, nfqws2HookAudits(t, a))
	}
	if nfqws2HookAuditReason("Kernel/../x") != nfqws2HookReasonFailed || nfqws2HookAuditReason("") != nfqws2HookReasonFailed || nfqws2HookAuditReason(dataplane.NFQWS2HookReasonQueue) != "queue-binding" {
		t.Fatal("audit path accepts an unfixed code")
	}
}

// The repair maintains the route already applied: Autopilot disabled and
// the manual mode do not stop it, and its outcome never compounds the
// shared node-recovery schedule.
func TestNFQWS2HookRepairRunsInNodeRecoveryWhileAutopilotPaused(t *testing.T) {
	for _, outcome := range []string{"restored", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			a, plan, model := nfqws2HookAppFixture(t)
			if outcome == "failed" {
				model.restore = nfqws2HookFailure(dataplane.NFQWS2HookReasonVerify)
			}
			mode := "manual"
			if err := a.Store.UpdateServiceControl(&mode, nil, a.Store.Get().Revision); err != nil {
				t.Fatal(err)
			}
			if cfg := a.Store.Get(); cfg.ServiceControl.EffectiveMode() != "manual" || cfg.AppliedRevision != plan.Revision || a.autonomyPolicy().Enabled {
				t.Fatal("fixture is not a paused Autopilot with the applied plan")
			}
			now := time.Now()
			initRecoveryScheduleFixture(t, a, now)
			a.reconcileRound(context.Background(), now)
			if model.observed != 1 || model.restored != 1 {
				t.Fatal("paused Autopilot blocked the repair", model)
			}
			op := recoveryScheduleOperation(t, a)
			if op.State != "completed" || op.Attempts != 0 || !op.NextRun.Equal(now.Add(30*time.Second)) {
				t.Fatalf("repair outcome changed the shared schedule: %+v", op)
			}
			for _, other := range a.reconciler.doc.Operations {
				if other.Kind != "node-recovery" && !other.NextRun.Equal(now.Add(time.Hour)) {
					t.Fatalf("repair dispatched another task: %+v", other)
				}
			}
		})
	}
}

func TestReconcilerNarrowWakeMakesOnlyNodeRecoveryDue(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	if a.wakeNodeRecoveryOnly() {
		t.Fatal("wake without a loop reported success")
	}
	a.reconciler.wake = make(chan struct{}, 1)
	a.reconciler.mu.Lock()
	for i := range a.reconciler.doc.Operations {
		a.reconciler.doc.Operations[i].NextRun = now.Add(time.Hour)
	}
	a.reconciler.doc.Operations[0].Attempts = 3
	a.reconciler.mu.Unlock()
	if !a.wakeNodeRecoveryOnly() || !a.wakeNodeRecoveryOnly() {
		t.Fatal("idle node recovery refused a wake")
	}
	if len(a.reconciler.wake) != 1 {
		t.Fatal("wake did not nudge the loop exactly once")
	}
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind == "node-recovery" && (op.NextRun.After(time.Now()) || op.Attempts != 0) {
			t.Fatalf("node recovery not made due: %+v", op)
		}
		if op.Kind != "node-recovery" && !op.NextRun.Equal(now.Add(time.Hour)) {
			t.Fatalf("narrow wake made %s due", op.Kind)
		}
	}
	a.reconcileRound(context.Background(), time.Now())
	if model.observed != 1 {
		t.Fatal("woken round did not observe", model.observed)
	}
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind != "node-recovery" && !op.NextRun.Equal(now.Add(time.Hour)) {
			t.Fatalf("woken round ran %s", op.Kind)
		}
	}
	// A running task keeps its own next run; the hint must try again.
	a.reconciler.mu.Lock()
	a.reconciler.doc.Operations[0].State, a.reconciler.doc.Operations[0].NextRun = "running", now.Add(time.Hour)
	a.reconciler.mu.Unlock()
	if a.wakeNodeRecoveryOnly() || !a.reconciler.doc.Operations[0].NextRun.Equal(now.Add(time.Hour)) {
		t.Fatal("wake overwrote a running node recovery")
	}
	// The broad wake keeps its semantics: settings changes refresh all.
	a.reconciler.doc.Operations[0].State = "completed"
	a.wakeReconciler()
	for _, op := range a.reconciler.doc.Operations {
		if op.Kind != "legacy-routes" && op.NextRun.After(time.Now()) {
			t.Fatalf("wakeReconciler no longer makes %s due", op.Kind)
		}
	}
}
