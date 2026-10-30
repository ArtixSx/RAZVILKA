//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// This is a controller/config/Manager persistence model, not native evidence.
// Native source facts and boot hook settlement are explicit private leaves.
// Actual Manager.Apply/Deactivate/Recover, config disk CAS, outer WAL codec,
// application hook settlement, fences and ordinary Resume execute unchanged.
type offlineNFQStopModel struct {
	a                               *App
	configPath, dnsPath, state      string
	before                          config.Config
	plan                            dataplane.Plan
	source                          dataplane.NFQWS2OfflineStopEvidence
	stopped                         bool
	metadataRunning                 bool
	stopCalls, activations, retries int
	refuseHooks                     bool
	failStop                        bool
	inspectHook                     func()
}

func newOfflineNFQStopModel(t *testing.T) *offlineNFQStopModel {
	t.Helper()
	a, _, before := recoveryStopFixture(t)
	state := a.Dataplane.StateRoot
	plan, _, err := a.Dataplane.Committed()
	if err != nil {
		t.Fatal(err)
	}
	f := &offlineNFQStopModel{a: a, state: state, configPath: filepath.Join(filepath.Dir(state), "config.json"), dnsPath: filepath.Join(filepath.Dir(state), "dns.json"), before: before, plan: plan}
	f.source = dataplane.NFQWS2OfflineStopEvidence{Binding: strings.Repeat("a", 64), RuntimeRoot: filepath.Join(state, "runtime", "nfqws2"), RuntimeOwner: "1:2", Network: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 12}, Instance: strings.Repeat("b", 24), Lease: []byte("original running lease model"), StoppedLease: []byte("exact stopped lease model"), Files: make([]restorejournal.Image, 11), FileOwners: make([]string, 11)}
	for i := range f.source.Files {
		f.source.Files[i] = restorejournal.Image{Exists: true, Data: []byte(fmt.Sprintf("original file %d", i))}
		f.source.FileOwners[i] = fmt.Sprintf("file-%d", i)
	}
	f.source.Files[0].Data = append([]byte(nil), f.source.Lease...)
	// Replace the fixture's adapter registry, retaining its actual committed
	// plan/execution files. Only native command observation is modeled here.
	f.a.Dataplane = dataplane.New(state)
	f.bind(t)
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	f.writePendingHooks(t)
	return f
}

func (f *offlineNFQStopModel) bind(t *testing.T) {
	t.Helper()
	ad := &serviceRuntimeAdapter{name: "nfqws2", nodeApplyAdapter: &nodeApplyAdapter{}}
	ad.after = func(phase string) error {
		switch phase {
		case "deactivate":
			f.stopCalls++
			if f.failStop {
				return errors.New("modeled cleanup failure")
			}
			f.stopped, f.refuseHooks, f.metadataRunning = true, false, false
		case "activate":
			f.activations++
			f.stopped = false
		}
		return nil
	}
	if err := f.a.Dataplane.Register(ad); err != nil {
		t.Fatal(err)
	}
	f.a.FreshProfile = stableNodeProfile
	f.a.Dataplane.FreshProfile = stableNodeProfile
	f.a.DataplaneHost = func() dataplane.HostState {
		return dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}
	}
	f.a.nodeReviews.options = func() []routecatalog.Option {
		return []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "nfqws2", Installed: true, Configured: true, Selectable: true}}
	}
	if f.a.EngineConfigs == nil {
		f.a.EngineConfigs = engineconfig.New(filepath.Join(filepath.Dir(f.state), "stage"), filepath.Join(filepath.Dir(f.state), "backup"))
		if _, err := f.a.EngineConfigs.Stage("nfqws2", "user-list", "pending-editor.example\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *offlineNFQStopModel) restart(t *testing.T) {
	t.Helper()
	s, err := config.LoadExisting(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	prior := f.a
	f.a = &App{Store: s, Dataplane: dataplane.New(f.state), Catalog: prior.Catalog, EngineConfigs: prior.EngineConfigs}
	f.bind(t)
	if err := f.a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
}

func (f *offlineNFQStopModel) writePendingHooks(t *testing.T) {
	t.Helper()
	j := nfqws2HookJournal{Version: 1, State: "pending", Reason: "cleanup-unknown", Plan: f.plan, Instance: f.source.Instance, Started: time.Now().UTC().Add(-time.Second)}
	raw, _ := json.Marshal(j)
	if err := os.WriteFile(filepath.Join(f.state, nfqws2HookJournalName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	boot := struct {
		Version  int    `json:"version"`
		PlanID   string `json:"plan_id"`
		Digest   string `json:"digest"`
		Instance string `json:"instance"`
		State    string `json:"state"`
		Effects  []any  `json:"effects"`
	}{1, f.plan.PlanID, f.plan.Digest, f.source.Instance, "uncertain", []any{struct {
		Command dataplane.NFQWS2HookCommand `json:"command"`
		State   string                      `json:"state"`
	}{dataplane.NFQWS2HookCommand{Family: 4, Args: []string{"-t", "mangle", "-N", "nfqws_post"}}, "unknown"}}}
	raw, _ = json.Marshal(boot)
	if err := os.WriteFile(filepath.Join(f.state, "nfqws2-boot-hooks.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *offlineNFQStopModel) evidence() dataplane.NFQWS2OfflineStopEvidence {
	raw, _ := json.Marshal(f.source)
	var e dataplane.NFQWS2OfflineStopEvidence
	_ = json.Unmarshal(raw, &e)
	if f.stopped {
		if !f.metadataRunning {
			e.Lease = append([]byte(nil), e.StoppedLease...)
			e.Files[0].Data = append([]byte(nil), e.Lease...)
			e.FileOwners[0] = "phase-only-lease-rename"
		}
		for _, i := range []int{2, 4} {
			e.Files[i] = restorejournal.Image{}
			e.FileOwners[i] = ""
		}
	}
	return e
}

func (f *offlineNFQStopModel) native(t *testing.T) offlineNFQStopNative {
	t.Helper()
	inactive := func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !f.stopped {
			return errors.New("modeled native runtime remains")
		}
		return nil
	}
	n := offlineNFQStopNative{inspect: func(ctx context.Context, p dataplane.Plan) (dataplane.NFQWS2OfflineStopEvidence, error) {
		if f.inspectHook != nil {
			f.inspectHook()
		}
		if ctx.Err() != nil {
			return dataplane.NFQWS2OfflineStopEvidence{}, ctx.Err()
		}
		if !reflect.DeepEqual(p, f.plan) {
			return dataplane.NFQWS2OfflineStopEvidence{}, dataplane.ErrReviewChanged
		}
		return f.evidence(), nil
	}, inactive: inactive}
	n.retry = func(ctx context.Context) error {
		f.retries++
		raw, err := os.ReadFile(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName))
		if err != nil {
			return err
		}
		in, err := dataplane.DecodeNFQWS2OfflineStopIntent(raw)
		if err != nil || in.State != "pending" || !f.evidence().Matches(in.Source, false) {
			return dataplane.ErrReviewChanged
		}
		return inactive(ctx)
	}
	n.hooks = func(ctx context.Context, at time.Time) (func() error, func() error, func(), error) {
		if f.refuseHooks {
			return nil, nil, nil, errors.New("modeled interrupted running metadata")
		}
		root, err := openNFQWS2HookJournal(f.state)
		if err != nil {
			return nil, nil, nil, err
		}
		j, raw, err := readNFQWS2HookJournal(root)
		if err != nil {
			root.Close()
			return nil, nil, nil, err
		}
		appSettle := func() error { return nil }
		if j.State == "pending" {
			owner := &nfqws2HookJournalOwner{path: f.state, root: root, image: raw, record: j}
			appSettle = nfqws2HookStopSettlementAt(ctx, f.a.Dataplane, owner, func() error { return inactive(ctx) }, at)
		}
		bootRaw, err := root.ReadLimited("nfqws2-boot-hooks.json", 1<<20)
		if err != nil {
			root.Close()
			return nil, nil, nil, err
		}
		after, pending, err := dataplane.ReviewedNFQWS2BootHookStopImage(bootRaw, f.plan, f.source.Instance)
		if err != nil {
			root.Close()
			return nil, nil, nil, err
		}
		bootSettle := func() error {
			if !pending {
				return nil
			}
			if err := inactive(ctx); err != nil {
				return err
			}
			p, ok, err := f.a.Dataplane.Committed()
			if err != nil || !ok || !reflect.DeepEqual(p, f.plan) {
				return dataplane.ErrReviewChanged
			}
			actual, err := root.ReadLimited("nfqws2-boot-hooks.json", 1<<20)
			if err != nil || !bytes.Equal(actual, bootRaw) {
				return dataplane.ErrReviewChanged
			}
			if err := root.WriteAtomic("nfqws2-boot-hooks.json", after, 0600); err != nil {
				return err
			}
			return root.Sync()
		}
		return appSettle, bootSettle, func() { _ = root.Close() }, nil
	}
	n.publication = func(ctx context.Context, prior, target dataplane.Plan, original map[string]restorejournal.Image) (dataplane.OfflineNFQWS2StopPublication, error) {
		if err := inactive(ctx); err != nil {
			return dataplane.OfflineNFQWS2StopPublication{}, err
		}
		root, err := openNFQWS2HookJournal(f.state)
		if err != nil {
			return dataplane.OfflineNFQWS2StopPublication{}, err
		}
		defer root.Close()
		images := map[string]restorejournal.Image{}
		for _, name := range []string{"latest-plan.json", "latest-committed-plan.json", "latest-execution.json", filepath.Join("transactions", target.PlanID, "execution.json")} {
			image, err := readOfflineNFQImage(root, name, 1<<20)
			if err != nil {
				return dataplane.OfflineNFQWS2StopPublication{}, err
			}
			images[name] = image
		}
		p := dataplane.OfflineNFQWS2StopPublication{Before: images, After: images}
		return p, dataplane.ValidateNFQWS2EmptyStopPublication(prior, target, original, p)
	}
	n.complete = func(ctx context.Context, prior, target dataplane.Plan, original map[string]restorejournal.Image, p dataplane.OfflineNFQWS2StopPublication) error {
		if err := inactive(ctx); err != nil {
			return err
		}
		if err := dataplane.ValidateNFQWS2EmptyStopPublication(prior, target, original, p); err != nil {
			return err
		}
		return f.a.Dataplane.ObserveNFQWS2EmptyStopPublication(ctx, prior, target, original, &p)
	}
	return n
}

func (f *offlineNFQStopModel) run(t *testing.T, native offlineNFQStopNative) (OfflineNFQWS2StopResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runOfflineNFQWS2Stop(ctx, f.a.Dataplane, f.a.Store, f.configPath, f.dnsPath, native)
}

func (f *offlineNFQStopModel) assertStopped(t *testing.T) {
	t.Helper()
	cfg := f.a.Store.Get()
	if !cfg.ServiceControl.Stopped || cfg.SafeMode || len(cfg.AppliedServices) != 0 || !reflect.DeepEqual(cfg.Services, f.before.Services) || !reflect.DeepEqual(cfg.ServiceControl.SuspendedServices, f.before.AppliedServices) || len(cfg.ServiceControl.SuspendedRoutes) != len(f.plan.Routes) {
		t.Fatal("Stop lost applied/desired scope")
	}
	p, ok, err := f.a.Dataplane.Committed()
	if err != nil || !ok || !p.Noop || p.State != "committed" || len(p.Routes) != 0 || len(p.Adapters) != 0 || p.Revision != cfg.AppliedRevision {
		t.Fatal("Stop lacks real empty committed plan", err)
	}
	if err := CheckOfflineNFQWS2Stop(f.state); err != nil {
		t.Fatal("completed intent still fences", err)
	}
	boot, _ := os.ReadFile(filepath.Join(f.state, "nfqws2-boot-hooks.json"))
	if !bytes.Contains(boot, []byte(`"state":"unknown"`)) {
		t.Fatal("Stop erased unknown original effect")
	}
	if f.activations != 0 {
		t.Fatal("Stop activated a runtime")
	}
}

func TestOfflineNFQWS2StopEveryCrashStageReopensExactIntent(t *testing.T) {
	for _, stage := range []string{"intent", "deactivated", "app-settled", "boot-settled", "inactive", "applying", "plan", "publication", "config", "complete"} {
		t.Run(stage, func(t *testing.T) {
			f := newOfflineNFQStopModel(t)
			n := f.native(t)
			crash := errors.New("modeled process termination")
			hit := false
			n.checkpoint = func(at string) error {
				if at == stage {
					hit = true
					return crash
				}
				return nil
			}
			if _, err := f.run(t, n); !errors.Is(err, crash) || !hit {
				t.Fatalf("stage %s not reached: %v", stage, err)
			}
			if stage != "complete" && CheckOfflineNFQWS2Stop(f.state) == nil {
				t.Fatal("pending Stop unfenced")
			}
			// Discard all in-memory Store/Manager/outer journal objects.
			f.restart(t)
			if stage != "complete" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, release, err := f.a.Operations.ExclusiveContext(ctx)
				cancel()
				if err == nil {
					release()
					t.Fatal("HTTP admission bypassed pending Stop")
				}
			}
			result, err := f.run(t, f.native(t))
			if err != nil || !result.Stopped {
				t.Fatal("fresh invocation failed", err)
			}
			f.assertStopped(t)
		})
	}
}

func TestOfflineNFQWS2StopPersistentRestartAndOrdinaryResume(t *testing.T) {
	f := newOfflineNFQStopModel(t)
	if _, err := f.run(t, f.native(t)); err != nil {
		t.Fatal(err)
	}
	f.assertStopped(t)
	for i := 0; i < 2; i++ {
		f.restart(t)
		before := f.a.Store.Get()
		r, err := f.a.Dataplane.Recover(context.Background())
		if err != nil || r.Guarded || r.State != "skipped" || !reflect.DeepEqual(before, f.a.Store.Get()) || f.activations != 0 {
			t.Fatalf("stopped boot %d replayed old intent: %+v %v", i, r, err)
		}
	}
	ctx, release, err := f.a.scopedRuntimeOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := f.a.executeServiceRuntime(ctx, "resume", f.a.Store.Get().Revision)
	release()
	if out.Code != "" {
		t.Fatal("ordinary Resume failed", out.Code, out.Message)
	}
	after := f.a.Store.Get()
	if after.ServiceControl.Stopped || !reflect.DeepEqual(after.AppliedServices, f.before.AppliedServices) || !reflect.DeepEqual(after.Services, f.before.Services) || f.activations != 1 {
		t.Fatal("Resume widened/lost exact saved scope")
	}
	if draft, err := f.a.EngineConfigs.ReadExpert("nfqws2", "user-list"); err != nil || draft.Source != "staged" {
		t.Fatal("Resume consumed pending editor draft", err)
	}
}

func TestOfflineNFQWS2StopConfigCASRejectsEveryRetryEdit(t *testing.T) {
	for _, stage := range []string{"intent", "deactivated", "app-settled", "boot-settled", "inactive", "applying", "plan", "publication", "config"} {
		t.Run(stage, func(t *testing.T) {
			f := newOfflineNFQStopModel(t)
			n := f.native(t)
			n.checkpoint = func(at string) error {
				if at == stage {
					return errors.New("crash")
				}
				return nil
			}
			if _, err := f.run(t, n); err == nil {
				t.Fatal("crash absent")
			}
			raw, err := os.ReadFile(f.configPath)
			if err != nil {
				t.Fatal(err)
			}
			changed := append(append([]byte(nil), raw...), '\n')
			if err := os.WriteFile(f.configPath, changed, 0600); err != nil {
				t.Fatal(err)
			}
			f.restart(t)
			calls := f.stopCalls
			if _, err := f.run(t, f.native(t)); err == nil {
				t.Fatal("fresh Store adopted changed raw original config")
			}
			after, _ := os.ReadFile(f.configPath)
			if !bytes.Equal(after, changed) || f.stopCalls != calls {
				t.Fatal("refused retry changed config/runtime")
			}
		})
	}
}

func TestOfflineNFQWS2StopRetriesAfterUncertainIntentSync(t *testing.T) {
	f := newOfflineNFQStopModel(t)
	n := f.native(t)
	failed := errors.New("directory sync failed")
	n.syncRoot = func(*ownedfs.Root) error { return failed }
	if _, err := f.run(t, n); !errors.Is(err, failed) || f.stopCalls != 0 {
		t.Fatal("effect before durable intent", err)
	}
	f.restart(t)
	n = f.native(t)
	n.syncRoot = func(*ownedfs.Root) error { return failed }
	if _, err := f.run(t, n); !errors.Is(err, failed) || f.stopCalls != 0 {
		t.Fatal("retry reused visible but unsynced intent", err)
	}
	f.restart(t)
	if _, err := f.run(t, f.native(t)); err != nil {
		t.Fatal("durable retry failed", err)
	}
	f.assertStopped(t)
}

func TestOfflineNFQWS2StopFailureKeepsUpdaterQuiescenceDistinct(t *testing.T) {
	f := newOfflineNFQStopModel(t)
	before := f.a.Store.Get()
	if _, err := f.a.Dataplane.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.a.Store.Get()) {
		t.Fatal("generic Deactivate changed Store intent")
	}
	if _, err := os.Stat(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generic updater cleanup wrote user Stop WAL")
	}
	f.failStop = true
	if _, err := f.run(t, f.native(t)); err == nil {
		t.Fatal("failed cleanup claimed stopped")
	}
	if !reflect.DeepEqual(before, f.a.Store.Get()) || CheckOfflineNFQWS2Stop(f.state) == nil || f.activations != 0 {
		t.Fatal("failure lost gates or resumed")
	}
}

func TestOfflineNFQWS2StopReopensExplicitEmptyConfigMap(t *testing.T) {
	f := newOfflineNFQStopModel(t)
	raw, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["service_policies"] = json.RawMessage(`{}`)
	raw, _ = json.MarshalIndent(fields, "", "  ")
	if err := os.WriteFile(f.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	if f.a.Store.Get().ServicePolicies == nil {
		t.Fatal("fixture did not preserve explicit empty config map")
	}
	f.before = f.a.Store.Get()
	n := f.native(t)
	n.checkpoint = func(at string) error {
		if at == "plan" {
			return errors.New("crash before config CAS")
		}
		return nil
	}
	if _, err := f.run(t, n); err == nil {
		t.Fatal("crash absent")
	}
	f.restart(t)
	intentRaw, _ := os.ReadFile(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName))
	intent, err := dataplane.DecodeNFQWS2OfflineStopIntent(intentRaw)
	if err != nil || intent.ConfigBefore.ServicePolicies != nil || f.a.Store.Get().ServicePolicies == nil {
		t.Fatal("fixture did not cross omitted-map journal roundtrip", err)
	}
	if _, err := f.run(t, f.native(t)); err != nil {
		t.Fatal("exact raw before image with omitted map cannot finish", err)
	}
	f.assertStopped(t)
}

func TestOfflineNFQWS2StopSecondEpochArchiveCrashIsIdempotent(t *testing.T) {
	f := newOfflineNFQStopModel(t)
	if _, err := f.run(t, f.native(t)); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, err := f.a.scopedRuntimeOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := f.a.executeServiceRuntime(ctx, "resume", f.a.Store.Get().Revision)
	release()
	if out.Code != "" {
		t.Fatal("ordinary Resume failed", out.Code, out.Message)
	}
	f.before = f.a.Store.Get()
	f.plan, _, err = f.a.Dataplane.Committed()
	if err != nil {
		t.Fatal(err)
	}
	f.source.Instance = strings.Repeat("c", 24)
	f.source.Lease = []byte("next exact running generation")
	f.source.StoppedLease = []byte("next exact stopped generation")
	f.source.Files[0].Data = append([]byte(nil), f.source.Lease...)
	f.activations = 0 // This assertion now measures the second explicit Stop.
	f.writePendingHooks(t)
	n := f.native(t)
	crash := errors.New("crash after archive link before new intent")
	n.checkpoint = func(stage string) error {
		if stage == "history" {
			return crash
		}
		return nil
	}
	calls := f.stopCalls
	if _, err := f.run(t, n); !errors.Is(err, crash) || f.stopCalls != calls {
		t.Fatal("archive crash was not before native effects", err)
	}
	current, _ := os.ReadFile(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName))
	if !bytes.Equal(current, first) {
		t.Fatal("archive crash replaced previous completed intent")
	}
	history := filepath.Join(f.state, "offline-nfqws2-stop-history")
	entries, err := os.ReadDir(history)
	if err != nil || len(entries) != 1 {
		t.Fatal("completed history not durably retained", err)
	}
	archived, _ := os.ReadFile(filepath.Join(history, entries[0].Name()))
	if !bytes.Equal(archived, first) {
		t.Fatal("archive lost complete original history")
	}
	f.restart(t)
	if _, err := f.run(t, f.native(t)); err != nil {
		t.Fatal("exact existing history link prevented retry", err)
	}
	f.assertStopped(t)
	archived, _ = os.ReadFile(filepath.Join(history, entries[0].Name()))
	if !bytes.Equal(archived, first) {
		t.Fatal("second epoch overwrote first epoch history")
	}
}

func TestOfflineNFQWS2StopCompletedSuccessClosesFreshObservation(t *testing.T) {
	for _, change := range []string{"runtime-live", "config", "plan", "hooks", "recovery"} {
		t.Run(change, func(t *testing.T) {
			f := newOfflineNFQStopModel(t)
			if _, err := f.run(t, f.native(t)); err != nil {
				t.Fatal(err)
			}
			f.restart(t)
			walPath := filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName)
			walBefore, _ := os.ReadFile(walPath)
			calls := f.stopCalls
			n := f.native(t)
			inactive := n.inactive
			observations := 0
			var changedPath string
			var changedBytes []byte
			n.inactive = func(ctx context.Context) error {
				observations++
				if change == "runtime-live" {
					return errors.New("fresh modeled kernel observation is live")
				}
				if observations == 2 { // The final guard's native observation.
					switch change {
					case "config":
						changedPath = f.configPath
					case "plan":
						changedPath = filepath.Join(f.state, "latest-committed-plan.json")
					case "hooks":
						changedPath = filepath.Join(f.state, nfqws2HookJournalName)
					case "recovery":
						changedPath = filepath.Join(f.state, "latest-recovery.json")
					}
					before, err := os.ReadFile(changedPath)
					if err != nil {
						return err
					}
					changedBytes = append(before, '\n')
					if err := os.WriteFile(changedPath, changedBytes, 0600); err != nil {
						return err
					}
				}
				return inactive(ctx)
			}
			result, err := f.run(t, n)
			if err == nil || result.Stopped || observations == 0 || f.stopCalls != calls {
				t.Fatal("historical complete record escaped fresh observation", err)
			}
			walAfter, _ := os.ReadFile(walPath)
			if !bytes.Equal(walBefore, walAfter) {
				t.Fatal("refusal rewrote historical complete intent")
			}
			if changedPath != "" {
				after, _ := os.ReadFile(changedPath)
				if !bytes.Equal(after, changedBytes) {
					t.Fatal("refusal overwrote changed evidence")
				}
			}
		})
	}
}

func TestOfflineNFQWS2StopInterruptedCleanupNeedsExistingIntentAndFreshAbsence(t *testing.T) {
	for _, mode := range []string{"new-request", "pending-live", "pending-gone"} {
		t.Run(mode, func(t *testing.T) {
			f := newOfflineNFQStopModel(t)
			if mode != "new-request" {
				n := f.native(t)
				n.checkpoint = func(stage string) error {
					if stage == "intent" {
						return errors.New("crash after durable intent")
					}
					return nil
				}
				if _, err := f.run(t, n); err == nil {
					t.Fatal("crash absent")
				}
			}
			f.refuseHooks = true
			if mode == "pending-gone" {
				// owned_stop removed the daemon/run/PID but died before writing
				// the stopped phase. Retain the exact original running receipt.
				f.stopped, f.metadataRunning = true, true
			}
			f.restart(t)
			result, err := f.run(t, f.native(t))
			if mode == "pending-gone" {
				if err != nil || !result.Stopped || f.retries != 1 || f.stopCalls != 1 {
					t.Fatal("exact inactive interrupted cleanup cannot retry", err)
				}
				f.assertStopped(t)
				return
			}
			if err == nil || result.Stopped || f.stopCalls != 0 || !reflect.DeepEqual(f.a.Store.Get(), f.before) {
				t.Fatal("unknown/live admission bypassed original Stop review", err)
			}
			if mode == "new-request" {
				if f.retries != 0 {
					t.Fatal("new request used retry waiver")
				}
				if _, err := os.Stat(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused new request created its own retry authority")
				}
			} else if f.retries != 1 || CheckOfflineNFQWS2Stop(f.state) == nil {
				t.Fatal("refused pending retry lost fence")
			}
		})
	}
}

func TestOfflineNFQWS2StopCanonicalFenceClosesAlreadyRunningAlternateApp(t *testing.T) {
	f := newOfflineNFQStopModel(t)
	alternate := &App{Dataplane: dataplane.New(filepath.Join(t.TempDir(), "alternate-state"))}
	// Use a fixture for the fixed installation root; the public initializer
	// always passes installpath.State/dataplane, independent of app flags.
	if err := alternate.initializeComponentRecoveryGate(f.state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, release, err := alternate.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal("absent canonical outer Stop incorrectly fenced app", err)
	}
	release()
	n := f.native(t)
	n.checkpoint = func(stage string) error {
		if stage == "intent" {
			return errors.New("canonical Stop is now durably pending")
		}
		return nil
	}
	if _, err := f.run(t, n); err == nil {
		t.Fatal("pending intent absent")
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName))
	for _, admitted := range []context.Context{ctx, componentStopContext(ctx, "stop"), context.WithValue(ctx, componentAdmissionKey{}, componentAdmission{inspect: true})} {
		_, release, err := alternate.Operations.ExclusiveContext(admitted)
		if release != nil {
			release()
		}
		if !errors.Is(err, ErrOfflineNFQWS2Stop) {
			t.Fatal("alternate state or narrow component permission bypassed canonical Stop", err)
		}
	}
	after, _ := os.ReadFile(filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName))
	if !bytes.Equal(raw, after) || f.stopCalls != 0 {
		t.Fatal("cross-root admission mutated pending Stop")
	}
}
