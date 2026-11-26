package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func firstStartRetiringSnapshotFixture(t *testing.T) (*NFQWS2Adapter, Plan, Plan) {
	t.Helper()
	f := newStockAdapterFixture(t)
	previous := f.plan
	previous.PlanID, previous.State, previous.Revision = "dp-1111111111111111", "committed", 1
	stop := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-2222222222222222", Digest: strings.Repeat("b", 64), Revision: 2, RetiringAdapters: []string{"nfqws2"}}
	raw, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.a.owner()
	if err != nil {
		t.Fatal(err)
	}
	config, err := f.a.firstStartConfig(previous, raw)
	if err != nil {
		t.Fatal(err)
	}
	init, err := engineconfig.NFQWSFirstStartInit(readBytes(t, f.a.InitPath), owner)
	if err != nil {
		t.Fatal(err)
	}
	writeStockText(t, f.a.ConfigPath, string(config))
	writeStockText(t, f.a.InitPath, string(init))
	lease := &nfqws2Lease{Version: 1, StateRoot: f.a.StateRoot, Owner: owner, Transaction: filepath.Join(f.m.StateRoot, "transactions", previous.PlanID, "nfqws2"), ConfigPath: f.a.ConfigPath, InitPath: f.a.InitPath, ConfigHash: nfqws2Hash(config), InitHash: nfqws2Hash(init), FirstStart: &nfqws2FirstStartLease{Phase: nfqws2FirstStopped, PriorInitHash: nfqws2Hash(init), StockInitHash: engineconfig.NFQWSFirstStartStockInitSHA256, Process: &components.NFQWSRuntimeProcessIdentity{PID: 42, ParentPID: 1, Group: 42, BootID: "fixture", Start: "123", Executable: filepath.Join(filepath.Dir(f.a.InitPath), "nfqws2"), ArgumentsSHA256: strings.Repeat("a", 64)}}}
	for i, path := range f.a.ownedListPaths() {
		lease.Lists[i] = nfqws2ListLease{Path: path, BlockHash: strings.Repeat("a", 64)}
	}
	if err := f.a.writeLease(lease); err != nil {
		t.Fatal(err)
	}
	f.a.firstStartScopeRead = func(context.Context) ([]byte, string, error) { return nil, "eth3", nil }
	return f.a, stop, previous
}

func TestNFQWSFirstStartRetiringSnapshotUsesOwnedCommittedRecipe(t *testing.T) {
	a, stop, previous := firstStartRetiringSnapshotFixture(t)
	before := readBytes(t, a.ConfigPath)
	if err := a.Snapshot(context.Background(), stop, t.TempDir()); !errors.Is(err, engineconfig.ErrNFQWSFirstStart) {
		t.Fatal("empty target unexpectedly compiled", err)
	}
	root := t.TempDir()
	if err := a.snapshotRetiring(context.Background(), stop, previous, root); err != nil {
		t.Fatal("owned Stop snapshot rejected", err)
	}
	saved, err := readNFQWS2Snapshot(root)
	if err != nil || !saved.FirstStart || !bytes.Equal(saved.Config, before) || !bytes.Equal(readBytes(t, a.ConfigPath), before) {
		t.Fatal("retirement changed current recipe", err)
	}
	if _, exists, err := nfqws2Read(filepath.Join(root, "nfqws2.conf.staged")); err != nil || exists {
		t.Fatal("Stop staged runnable candidate", err)
	}
}

func TestNFQWSFirstStartRetiringSnapshotRejectsStaleOrExpandedScope(t *testing.T) {
	for _, kind := range []string{"not-retiring", "active-adapter", "active-route", "wrong-adapter", "uncommitted", "prior-adapter", "stale-transaction", "changed-scope", "changed-exclusion", "changed-recipe", "changed-config", "changed-init", "missing-owner", "foreign-owner", "unsettled", "scope-refused", "stop-draft", "prior-main-draft", "prior-list-draft"} {
		t.Run(kind, func(t *testing.T) {
			a, stop, previous := firstStartRetiringSnapshotFixture(t)
			switch kind {
			case "stop-draft":
				stop.EngineDrafts = []string{"nfqws2/main"}
			case "prior-main-draft", "prior-list-draft":
				stage, backup := t.TempDir(), t.TempDir()
				for _, path := range []string{stage, backup} {
					if err := os.Chmod(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				a.Configs = engineconfig.New(stage, backup)
				file, data := "main", string(readBytes(t, a.ConfigPath))
				if kind == "prior-list-draft" {
					file, data = "user-list", "foreign.example\n"
				}
				previous.EngineDrafts = []string{"nfqws2/" + file}
				if _, err := a.Configs.Stage("nfqws2", file, data); err != nil {
					t.Fatal(err)
				}
			case "not-retiring":
				stop.RetiringAdapters = nil
			case "active-adapter":
				stop.Adapters = []string{"nfqws2"}
			case "active-route":
				stop.Routes = previous.Routes
			case "wrong-adapter":
				stop.RetiringAdapters = []string{"xray"}
			case "uncommitted":
				previous.State = "draft"
			case "prior-adapter":
				previous.Adapters = []string{"xray"}
			case "stale-transaction":
				previous.PlanID = "dp-3333333333333333"
			case "changed-scope":
				previous.Routes[0].Domains = []string{"other.example"}
			case "changed-exclusion":
				previous.SiteExclusions = &SiteExclusions{Domains: []string{"other.example"}}
			case "changed-recipe":
				previous.NFQWSFirstStartRecipe = engineconfig.NFQWSFirstStartStockTLSCircular
			case "changed-config":
				writeStockText(t, a.ConfigPath, string(readBytes(t, a.ConfigPath))+"# foreign\n")
			case "changed-init":
				writeStockText(t, a.InitPath, string(readBytes(t, a.InitPath))+"# foreign\n")
			case "missing-owner":
				if err := a.writeLease(nil); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				lease, err := a.readLease()
				if err != nil {
					t.Fatal(err)
				}
				lease.Owner = strings.Repeat("b", 24)
				if err := a.writeLease(lease); err != nil {
					t.Fatal(err)
				}
			case "unsettled":
				lease, err := a.readLease()
				if err != nil {
					t.Fatal(err)
				}
				lease.FirstStart.Phase = nfqws2FirstStarting
				lease.FirstStart.Process = nil
				if err := a.writeLease(lease); err != nil {
					t.Fatal(err)
				}
			case "scope-refused":
				a.firstStartScopeRead = func(context.Context) ([]byte, string, error) { return nil, "foreign", nil }
			}
			root := t.TempDir()
			if err := a.snapshotRetiring(context.Background(), stop, previous, root); err == nil {
				t.Fatal("unsafe retirement snapshot admitted")
			}
			if _, exists, err := nfqws2Read(filepath.Join(root, "snapshot.json")); err != nil || exists {
				t.Fatal("refusal published snapshot", err)
			}
		})
	}
}

func TestNFQWS2FirstStartManagerStopThenResume(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.plan.PlanID, f.plan.Revision = "dp-1111111111111111", 1
	f.apply(t)
	first := f.identity
	stop := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-2222222222222222", Digest: strings.Repeat("b", 64), Revision: 2, Ready: true, RetiringAdapters: []string{"nfqws2"}}
	result, err := f.m.Apply(firstStartContext(t), stop, nil)
	if err != nil || result.State != "committed" {
		t.Fatal("manager Stop failed", result, err)
	}
	f.assertStopped(t)
	f.plan.PlanID, f.plan.Digest, f.plan.Revision = "dp-3333333333333333", strings.Repeat("c", 64), 3
	f.apply(t)
	if !f.running || f.identity.PID == first.PID {
		t.Fatal("resume did not acquire fresh runtime")
	}
	if err := f.a.Deactivate(firstStartContext(t)); err != nil {
		t.Fatal(err)
	}
	f.assertStopped(t)
}
