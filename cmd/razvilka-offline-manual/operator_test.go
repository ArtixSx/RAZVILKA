//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type operatorFixture struct {
	root   string
	p      paths
	pins   incident
	cfg    config.Config
	ctx    context.Context
	cancel context.CancelFunc
}

func fixtureHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func fixtureWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func fixtureJSON(t *testing.T, path string, value any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, path, raw, 0600)
	return raw
}

func fixtureRaw(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newOperatorFixture(t *testing.T) *operatorFixture {
	t.Helper()
	base := t.TempDir()
	opt := filepath.Join(base, "opt")
	p := paths{installation: opt, configDir: filepath.Join(opt, "etc/razvilka"), state: filepath.Join(opt, "var/lib/razvilka"), executable: filepath.Join(opt, "bin/razvilka"), init: filepath.Join(opt, "etc/init.d/S99razvilka"), pid: filepath.Join(opt, "var/run/razvilka.pid"), proc: filepath.Join(base, "proc")}
	for _, dir := range []string{p.configDir, p.state, filepath.Dir(p.executable), filepath.Dir(p.init), filepath.Dir(p.pid), p.proc} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f := &operatorFixture{root: base, p: p, ctx: ctx, cancel: cancel}
	// These executable sentinels would leave evidence if the operator started
	// an installed program or init script. The test itself never executes them.
	trap := []byte(fmt.Sprintf("#!/bin/sh\n: > '%s'\nexit 91\n", filepath.Join(base, "NATIVE_COMMAND_EXECUTED")))
	fixtureWrite(t, p.executable, trap, 0700)
	fixtureWrite(t, p.init, trap, 0700)
	fixtureWrite(t, filepath.Join(opt, "etc/init.d/S51nfqws2"), trap, 0700)
	for _, name := range []string{"nfqws2.conf", "nfqws2.conf.run", "lists/user.list", "lists/ipset.list", "lists/exclude.list", "lists/ipset_exclude.list"} {
		fixtureWrite(t, filepath.Join(opt, "etc/nfqws2", name), []byte("fixture-owned-"+name+"\n"), 0600)
	}
	for _, name := range []string{"admin.token", "admin.credentials.json", "config.json.automation.json", "config.json.automation.json.autonomy.json"} {
		fixtureWrite(t, filepath.Join(p.configDir, name), []byte("{\"fixture\":\""+name+"\"}"), 0600)
	}
	// Seed the actual Store's durable file lease before constructing a typed
	// incident image. runOperator subsequently uses the real strict Store/CAS.
	s, err := config.Load(filepath.Join(p.configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Get()
	cfg.Revision, cfg.AppliedRevision = 12, 11
	cfg.LastAppliedAt = "2026-10-30T17:58:31Z"
	cfg.ServiceControl.Mode = "auto"
	cfg.ServiceControl.Schedule = config.ServiceCheckSchedule{Enabled: true, ServiceIDs: []string{"youtube"}, IntervalSeconds: 600}
	cfg.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircularObserveAuto
	cfg.AppliedNFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircular
	cfg.CatalogPath = filepath.Join(p.configDir, "reviewed-catalog.json")
	cfg.EngineOrder = []string{"xray", "nfqws2", "sing-box"}
	for _, id := range []string{"nfqws2-common", "roblox", "youtube"} {
		state := config.ServiceState{Enabled: true, Mode: "nfqws2", Route: "nfqws2"}
		cfg.AppliedServices[id], cfg.Services[id] = state, state
	}
	cfg.Services["pending-service"] = config.ServiceState{Enabled: true, Mode: "xray", Route: "xray"}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 3, Manual: []config.ResourceMatch{{Kind: "exact", Value: "preserve.example"}}}
	policy := config.DefaultServicePolicy("youtube", cfg.AppliedServices["youtube"])
	policy.Enabled, policy.Mode, policy.Revision = true, "auto", 7
	cfg.ServicePolicies = map[string]config.ServicePolicy{"youtube": policy}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg, _, err = config.InspectBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	fixtureJSON(t, filepath.Join(p.configDir, "config.json"), f.cfg)
	if _, err := config.LoadExistingStrict(ctx, filepath.Join(p.configDir, "config.json")); err != nil {
		t.Fatalf("fixture is not a strict existing Store: %v", err)
	}
	if _, err := customservices.Load(filepath.Join(p.configDir, "custom-services.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Load(filepath.Join(p.configDir, "devices.json")); err != nil {
		t.Fatal(err)
	}
	for _, layout := range layouts(p) {
		c, out, err := privaterestore.Open(ctx, layout)
		if err != nil || out != restorejournal.Clean {
			t.Fatalf("initialize real generation: %v %v", out, err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	dp := filepath.Join(p.state, "dataplane")
	failedDigest, priorDigest := fixtureHash([]byte("failed fixture")), fixtureHash([]byte("prior fixture"))
	f.pins = incident{source: "fixture-source", binarySHA: fixtureHash(trap), initSHA: fixtureHash(trap), failedID: "dp-" + failedDigest[:16], failedDigest: failedDigest, priorID: "dp-" + priorDigest[:16], priorDigest: priorDigest}
	prior := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: f.pins.priorID, Digest: priorDigest, State: "committed", Revision: 11, Ready: true, RouteCount: 3, Adapters: []string{"nfqws2"}, NFQWSFirstStartRecipe: f.cfg.AppliedNFQWSFirstStartRecipe}
	for _, id := range []string{"nfqws2-common", "roblox", "youtube"} {
		prior.Routes = append(prior.Routes, dataplane.Route{ServiceID: id, Resolved: "nfqws2", Domains: []string{id + ".example"}})
	}
	failed := prior
	failed.PlanID, failed.Digest, failed.Revision, failed.State = f.pins.failedID, failedDigest, 12, "rolled-back"
	f.pins.failedPlanSHA = fixtureHash(fixtureJSON(t, filepath.Join(dp, "latest-plan.json"), failed))
	f.pins.priorPlanSHA = fixtureHash(fixtureJSON(t, filepath.Join(dp, "latest-committed-plan.json"), prior))
	now := "2026-10-30T19:39:16Z"
	execution := dataplane.Execution{PlanID: failed.PlanID, Digest: failed.Digest, State: "rolled-back", RollbackVerified: true, StartedAt: now, FinishedAt: now}
	for _, phase := range []string{"stage", "snapshot", "activate", "health", "rollback", "verify-rollback", "cleanup", "retry-rollback", "retry-verify-rollback"} {
		execution.Steps = append(execution.Steps, dataplane.ExecutionStep{Adapter: "nfqws2", Phase: phase, State: "passed", StartedAt: now, FinishedAt: now})
	}
	execution.Steps[3].State = "failed"
	fixtureJSON(t, filepath.Join(dp, "latest-execution.json"), execution)
	fixtureJSON(t, filepath.Join(dp, "transactions", failed.PlanID, "execution.json"), execution)
	f.pins.snapshotSHA = fixtureHash(fixtureJSON(t, filepath.Join(dp, "transactions", failed.PlanID, "nfqws2/snapshot.json"), map[string]string{"fixture": "preserved rollback snapshot"}))
	runtimeRoot := filepath.Join(dp, "runtime/nfqws2")
	owner := sha256.Sum256([]byte(runtimeRoot))
	lists := make([]map[string]string, 0, 4)
	for _, name := range []string{"user.list", "ipset.list", "exclude.list", "ipset_exclude.list"} {
		path := filepath.Join(opt, "etc/nfqws2/lists", name)
		lists = append(lists, map[string]string{"path": path, "block_hash": fixtureHash(fixtureRaw(t, path))})
	}
	lease := map[string]any{
		"version": 1, "state_root": runtimeRoot, "owner": hex.EncodeToString(owner[:12]), "transaction": filepath.Join(dp, "transactions", prior.PlanID, "nfqws2"),
		"config_path": filepath.Join(opt, "etc/nfqws2/nfqws2.conf"), "init_path": filepath.Join(opt, "etc/init.d/S51nfqws2"),
		"config_hash": fixtureHash(fixtureRaw(t, filepath.Join(opt, "etc/nfqws2/nfqws2.conf"))), "init_hash": fixtureHash(trap), "lists": lists,
		"first_start": map[string]any{"prior_init_hash": fixtureHash([]byte("prior init")), "stock_init_hash": engineconfig.NFQWSFirstStartStockInitSHA256, "phase": "running", "process": components.NFQWSRuntimeProcessIdentity{PID: 771, ParentPID: 1, Group: 771, Start: "12345", BootID: "fixture-boot", Executable: filepath.Join(opt, "bin/nfqws2"), ArgumentsSHA256: fixtureHash([]byte("arguments"))}},
	}
	fixtureJSON(t, filepath.Join(runtimeRoot, "ownership.json"), lease)
	return f
}

type fixtureFile struct {
	data []byte
	link string
	info os.FileInfo
}

func fixtureFiles(t *testing.T, root string) map[string]fixtureFile {
	t.Helper()
	out := map[string]fixtureFile{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		var file fixtureFile
		file.info = info
		if info.Mode()&os.ModeSymlink != 0 {
			file.link, err = os.Readlink(path)
		} else {
			file.data, err = os.ReadFile(path)
		}
		if err != nil {
			return err
		}
		out[path] = file
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func requireFixturePreserved(t *testing.T, root string, before map[string]fixtureFile, configChange string) {
	t.Helper()
	after := fixtureFiles(t, root)
	if len(before) != len(after) {
		t.Fatalf("operator created/removed files: before=%d after=%d", len(before), len(after))
	}
	for path, old := range before {
		now, ok := after[path]
		if !ok || old.info.Mode() != now.info.Mode() {
			t.Fatalf("file missing/mode changed: %s", path)
		}
		if path == configChange {
			continue
		}
		if !bytes.Equal(old.data, now.data) || old.link != now.link || !os.SameFile(old.info, now.info) || !old.info.ModTime().Equal(now.info.ModTime()) {
			t.Fatalf("operator changed preserved file: %s", path)
		}
	}
}

func requireOperatorRefusal(t *testing.T, got result, err error) {
	t.Helper()
	if err == nil || got.Outcome != "refused-before-write" || got.ManualSaved || got.PreservedEvidence || got.ConfigSHA256 != "" {
		t.Fatalf("failure advertised success: %+v err=%v", got, err)
	}
}

func TestOperatorRealStoreAndAllFourLifetimeLeases(t *testing.T) {
	f := newOperatorFixture(t)
	before := fixtureFiles(t, f.root)
	called := false
	got, err := runOperator(f.ctx, f.p, f.pins, func() {
		called = true
		for _, layout := range layouts(f.p) {
			other, _, err := privaterestore.Open(f.ctx, layout)
			if other != nil {
				_ = other.Close()
			}
			if !errors.Is(err, restorejournal.ErrBusy) {
				t.Fatalf("normal startup bypassed held generation %s: %v", filepath.Base(layout.JournalRoot), err)
			}
		}
	})
	if err != nil || !called || got.Outcome != "saved-manual-panel-left-stopped" || got.Stage != "completed" || !got.ManualSaved || !got.PreservedEvidence || got.PanelState != "stopped-confirmed-after-write" {
		t.Fatalf("save failed: %+v err=%v callback=%v", got, err, called)
	}
	path := filepath.Join(f.p.configDir, "config.json")
	s, err := config.LoadExistingStrict(f.ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	gotConfig := s.Get()
	want := f.cfg
	want.Revision++
	want.ServiceControl.Mode = "manual"
	if !reflect.DeepEqual(gotConfig, want) {
		t.Fatal("save changed more than mode and draft revision")
	}
	if got.BeforeRevision != f.cfg.Revision || got.AfterRevision != want.Revision || got.ConfigSHA256 != fixtureHash(fixtureRaw(t, path)) {
		t.Fatalf("unbound readback receipt: %+v", got)
	}
	requireFixturePreserved(t, f.root, before, path)
	// All four original OS leases must be released after successful readback.
	for _, layout := range layouts(f.p) {
		c, err := privaterestore.OpenForOfflineServiceControl(f.ctx, layout)
		if err != nil {
			t.Fatal("generation remained locked", err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOperatorAlreadyManualPreservesRawFileAndRevision(t *testing.T) {
	f := newOperatorFixture(t)
	f.cfg.ServiceControl.Mode = "manual"
	fixtureJSON(t, filepath.Join(f.p.configDir, "config.json"), f.cfg)
	before := fixtureFiles(t, f.root)
	got, err := runOperator(f.ctx, f.p, f.pins, nil)
	if err != nil || got.Outcome != "already-manual-panel-left-stopped" || got.BeforeRevision != f.cfg.Revision || got.AfterRevision != f.cfg.Revision || !got.ManualSaved || !got.PreservedEvidence {
		t.Fatalf("idempotent observation failed: %+v %v", got, err)
	}
	requireFixturePreserved(t, f.root, before, "")
}

func TestOperatorRejectsSameRevisionRawConfigDrift(t *testing.T) {
	for _, semantic := range []bool{false, true} {
		t.Run(fmt.Sprint("semantic-", semantic), func(t *testing.T) {
			f := newOperatorFixture(t)
			var changed map[string]fixtureFile
			got, err := runOperator(f.ctx, f.p, f.pins, func() {
				path := filepath.Join(f.p.configDir, "config.json")
				raw := append([]byte("\n"), fixtureRaw(t, path)...)
				if semantic {
					cfg := f.cfg
					cfg.CatalogPath += ".changed"
					raw, _ = json.Marshal(cfg)
				}
				fixtureWrite(t, path, raw, 0600)
				changed = fixtureFiles(t, f.root)
			})
			requireOperatorRefusal(t, got, err)
			if changed == nil || got.Stage != "source-closing-before-write" {
				t.Fatalf("source conflict did not reach intended boundary: %+v", got)
			}
			requireFixturePreserved(t, f.root, changed, "")
		})
	}
}

func TestOperatorCancellationBeforeCASPreservesEverything(t *testing.T) {
	f := newOperatorFixture(t)
	before := fixtureFiles(t, f.root)
	called := false
	got, err := runOperator(f.ctx, f.p, f.pins, func() { called = true; f.cancel() })
	requireOperatorRefusal(t, got, err)
	if !called || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
	requireFixturePreserved(t, f.root, before, "")
}

func TestOperatorRefusesBusyRealGeneration(t *testing.T) {
	for index := 0; index < 4; index++ {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			f := newOperatorFixture(t)
			c, _, err := privaterestore.Open(f.ctx, layouts(f.p)[index])
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			before := fixtureFiles(t, f.root)
			got, err := runOperator(f.ctx, f.p, f.pins, nil)
			requireOperatorRefusal(t, got, err)
			if !errors.Is(err, restorejournal.ErrBusy) || got.Stage != "private-lifetime-leases" {
				t.Fatalf("busy generation not enforced: %+v %v", got, err)
			}
			requireFixturePreserved(t, f.root, before, "")
		})
	}
}

func TestOperatorNeverCreatesAMissingGeneration(t *testing.T) {
	for index := 0; index < 4; index++ {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			f := newOperatorFixture(t)
			layout := layouts(f.p)[index]
			if err := os.RemoveAll(layout.JournalRoot); err != nil {
				t.Fatal(err)
			}
			before := fixtureFiles(t, f.root)
			got, err := runOperator(f.ctx, f.p, f.pins, nil)
			requireOperatorRefusal(t, got, err)
			if got.Stage != "private-lifetime-leases" {
				t.Fatalf("missing generation not fenced at lease admission: %+v", got)
			}
			requireFixturePreserved(t, f.root, before, "")
			if _, err := os.Lstat(layout.JournalRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("operator recreated the missing generation", err)
			}
		})
	}
}

type crashAfterRealConfigCAS struct{ *restorejournal.FileTarget }

func (target crashAfterRealConfigCAS) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if err := target.FileTarget.CompareAndSwap(ctx, before, after); err != nil {
		return err
	}
	panic("operator-test-crash-after-real-CAS")
}

func seedPendingGeneration(t *testing.T, f *operatorFixture, layout privaterestore.Layout) []byte {
	t.Helper()
	// Obtain the real coordinator's scope from a successful ordinary typed
	// restore. No copied scope algorithm or hand-crafted prepared JSON is used.
	c, _, err := privaterestore.Open(f.ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	payload := privatebackup.NewPayload("operator-integration-test")
	payload.Services["youtube"] = config.ServiceState{Enabled: true, Route: "direct"}
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	out, err := c.RestoreOffline(f.ctx, payload, map[string]bool{"youtube": true, "roblox": true, "nfqws2-common": true, "pending-service": true})
	closeErr := c.Close()
	if err != nil || closeErr != nil || out != restorejournal.Applied {
		t.Fatalf("scope-producing actual restore failed: %s %v %v", out, err, closeErr)
	}
	journalPath := filepath.Join(layout.JournalRoot, "restore.private.json")
	var settled struct {
		Scope string
		State string
	}
	if err := json.Unmarshal(fixtureRaw(t, journalPath), &settled); err != nil || settled.Scope == "" || settled.State != "idle" {
		t.Fatalf("actual idle scope unavailable: %v", err)
	}
	target, err := restorejournal.OpenExistingFileTarget(layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	j, err := restorejournal.OpenExisting(layout.JournalRoot, settled.Scope, map[string]restorejournal.Target{"config": crashAfterRealConfigCAS{target}})
	if err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	before := fixtureRaw(t, layout.Config)
	func() {
		defer func() {
			if recover() != "operator-test-crash-after-real-CAS" {
				t.Fatal("real prepared write boundary was not reached")
			}
		}()
		_, _ = j.Execute(f.ctx, map[string]restorejournal.Image{"config": {Exists: true, Data: append([]byte("\n"), before...)}})
	}()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	var pending struct{ State string }
	if err := json.Unmarshal(fixtureRaw(t, journalPath), &pending); err != nil || pending.State != "prepared" {
		t.Fatal("actual prepared receipt missing", err)
	}
	return before
}

func TestOperatorRefusesActualPendingGenerationWithoutReplay(t *testing.T) {
	for index := 0; index < 4; index++ {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			f := newOperatorFixture(t)
			layout := layouts(f.p)[index]
			beforeRestore := seedPendingGeneration(t, f, layout)
			before := fixtureFiles(t, f.root)
			got, err := runOperator(f.ctx, f.p, f.pins, nil)
			requireOperatorRefusal(t, got, err)
			if !errors.Is(err, restorejournal.ErrRecovery) || got.Stage != "private-lifetime-leases" {
				t.Fatalf("actual prepared generation not fenced: %+v %v", got, err)
			}
			requireFixturePreserved(t, f.root, before, "")
			// The ordinary coordinator still owns recovery of the same receipt.
			c, recovered, err := privaterestore.Open(f.ctx, layout)
			if err != nil || recovered != restorejournal.RolledBack {
				t.Fatalf("retained normal recovery was damaged: %s %v", recovered, err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeRestore, fixtureRaw(t, layout.Config)) {
				t.Fatal("normal recovery could not restore the original image")
			}
		})
	}
}

func TestOperatorRefusesWrongIncidentNonNFQWSAndBadLease(t *testing.T) {
	changes := map[string]func(*testing.T, *operatorFixture){
		"wrong-prior-digest": func(t *testing.T, f *operatorFixture) { f.pins.priorDigest = strings.Repeat("a", 64) },
		"rollback-not-verified": func(t *testing.T, f *operatorFixture) {
			path := filepath.Join(f.p.state, "dataplane/latest-execution.json")
			var e dataplane.Execution
			if err := json.Unmarshal(fixtureRaw(t, path), &e); err != nil {
				t.Fatal(err)
			}
			e.RollbackVerified = false
			fixtureJSON(t, path, e)
			fixtureJSON(t, filepath.Join(f.p.state, "dataplane/transactions", f.pins.failedID, "execution.json"), e)
		},
		"non-nfqws-prior": func(t *testing.T, f *operatorFixture) {
			path := filepath.Join(f.p.state, "dataplane/latest-committed-plan.json")
			var p dataplane.Plan
			if err := json.Unmarshal(fixtureRaw(t, path), &p); err != nil {
				t.Fatal(err)
			}
			p.Adapters, p.Routes[0].Resolved = []string{"sing-box"}, "sing-box"
			f.pins.priorPlanSHA = fixtureHash(fixtureJSON(t, path, p))
		},
	}
	for _, kind := range []string{"owner", "transaction", "phase", "process", "hash", "list-path"} {
		kind := kind
		changes["lease-"+kind] = func(t *testing.T, f *operatorFixture) {
			path := filepath.Join(f.p.state, "dataplane/runtime/nfqws2/ownership.json")
			var lease map[string]any
			if err := json.Unmarshal(fixtureRaw(t, path), &lease); err != nil {
				t.Fatal(err)
			}
			first := lease["first_start"].(map[string]any)
			switch kind {
			case "owner":
				lease["owner"] = strings.Repeat("a", 24)
			case "transaction":
				lease["transaction"] = filepath.Join(f.p.state, "dataplane/transactions", f.pins.failedID, "nfqws2")
			case "phase":
				first["phase"] = "stopped"
			case "process":
				delete(first, "process")
			case "hash":
				lease["init_hash"] = "invalid"
			case "list-path":
				lease["lists"].([]any)[0].(map[string]any)["path"] = filepath.Join(f.root, "foreign.list")
			}
			fixtureJSON(t, path, lease)
		}
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newOperatorFixture(t)
			change(t, f)
			before := fixtureFiles(t, f.root)
			got, err := runOperator(f.ctx, f.p, f.pins, nil)
			requireOperatorRefusal(t, got, err)
			if got.Stage != "exact-recovered-incident" {
				t.Fatalf("refusal occurred outside exact incident gate: %+v %v", got, err)
			}
			requireFixturePreserved(t, f.root, before, "")
		})
	}
}

func TestOperatorRefusesPIDFileAndNativeProcessReadback(t *testing.T) {
	for _, kind := range []string{"pidfile", "comm", "cmdline", "executable-deleted"} {
		t.Run(kind, func(t *testing.T) {
			f := newOperatorFixture(t)
			if kind == "pidfile" {
				fixtureWrite(t, f.p.pid, []byte("999999\n"), 0600)
			} else {
				proc := filepath.Join(f.p.proc, "424242")
				comm, args := "unrelated\n", []byte("unrelated\x00")
				if kind == "comm" {
					comm = "razvilka\n"
				}
				if kind == "cmdline" {
					args = []byte(f.p.executable + "\x00recover\x00")
				}
				fixtureWrite(t, filepath.Join(proc, "comm"), []byte(comm), 0600)
				fixtureWrite(t, filepath.Join(proc, "cmdline"), args, 0600)
				if kind == "executable-deleted" {
					if err := os.Symlink(f.p.executable+" (deleted)", filepath.Join(proc, "exe")); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := fixtureFiles(t, f.root)
			got, err := runOperator(f.ctx, f.p, f.pins, nil)
			requireOperatorRefusal(t, got, err)
			if got.Stage != "panel-and-paths" {
				t.Fatalf("process/pidfile not refused at initial observation: %+v", got)
			}
			requireFixturePreserved(t, f.root, before, "")
		})
	}
}

func TestOperatorClosingPanelObservationPreventsCAS(t *testing.T) {
	f := newOperatorFixture(t)
	var changed map[string]fixtureFile
	got, err := runOperator(f.ctx, f.p, f.pins, func() {
		fixtureWrite(t, f.p.pid, []byte("999999\n"), 0600)
		changed = fixtureFiles(t, f.root)
	})
	requireOperatorRefusal(t, got, err)
	if changed == nil || got.Stage != "source-closing-before-write" {
		t.Fatalf("late panel evidence did not reach closing observation: %+v %v", got, err)
	}
	requireFixturePreserved(t, f.root, changed, "")
}

func TestOperatorPreservedEvidenceDriftRefusesBeforeWrite(t *testing.T) {
	for _, kind := range []string{"execution", "ownership", "snapshot", "credentials", "autonomy", "installed-init"} {
		t.Run(kind, func(t *testing.T) {
			f := newOperatorFixture(t)
			var changed map[string]fixtureFile
			got, err := runOperator(f.ctx, f.p, f.pins, func() {
				dp := filepath.Join(f.p.state, "dataplane")
				path := map[string]string{"ownership": filepath.Join(dp, "runtime/nfqws2/ownership.json"), "snapshot": filepath.Join(dp, "transactions", f.pins.failedID, "nfqws2/snapshot.json"), "credentials": filepath.Join(f.p.configDir, "admin.credentials.json"), "autonomy": filepath.Join(f.p.configDir, "config.json.automation.json.autonomy.json"), "installed-init": f.p.init}[kind]
				if kind == "execution" {
					path = filepath.Join(dp, "latest-execution.json")
					var execution dataplane.Execution
					if err := json.Unmarshal(fixtureRaw(t, path), &execution); err != nil {
						t.Fatal(err)
					}
					execution.Error = "external retained-receipt change"
					fixtureJSON(t, path, execution)
					fixtureJSON(t, filepath.Join(dp, "transactions", f.pins.failedID, "execution.json"), execution)
				} else {
					fixtureWrite(t, path, append(fixtureRaw(t, path), '\n'), 0600)
				}
				changed = fixtureFiles(t, f.root)
			})
			requireOperatorRefusal(t, got, err)
			if changed == nil || got.Stage != "source-closing-before-write" {
				t.Fatalf("closing evidence check not reached: %+v %v", got, err)
			}
			requireFixturePreserved(t, f.root, changed, "")
		})
	}
}
