package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXrayFreshInstallAndLegacyOwnership(t *testing.T) {
	for _, test := range []struct {
		name, installed string
		script, denied  bool
	}{
		{"core-only-install", "", false, false},
		{"meta-and-core", "xray - 26.10.29-1\nxray-core - 26.10.29-1\n", false, true},
		{"old-meta", "xray - 26.3.27-1\n", false, true},
		{"orphan-vendor-script", "", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setup := t.TempDir()
			installed := test.installed
			if !test.denied {
				installed += "sing-box-go - 1.14.4-2\n"
			}
			r := &fakeRunner{output: map[string]string{"list-installed": installed, "install": "ok", "list": "xray-core - 26.10.29-1\nxray - 26.10.29-1\n", "update": "ok"}}
			m := &Manager{Opkg: "opkg", InitDir: setup, RepoDir: t.TempDir(), StateDir: t.TempDir(), Runner: r, Client: offlineReleases(), AdmitXrayCoreWrite: admitTestXray}
			path := filepath.Join(setup, "S24xray")
			if test.script {
				if err := os.WriteFile(path, []byte("ENABLED=yes\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			_, err := m.Apply(ctx, "xray")
			if (err != nil) != test.denied {
				t.Fatalf("result %v", err)
			}
			if test.denied {
				if _, err := m.Remove(ctx, "xray"); err == nil {
					t.Fatal("accepted foreign removal")
				}
				if _, err := m.ManagedUpdate(ctx, "xray", allowRecovery); err == nil {
					t.Fatal("accepted foreign update")
				}
				for _, call := range r.calls {
					if len(call) > 1 && (call[1] == "upgrade" || call[1] == "install" || call[1] == "remove") {
						t.Fatal("package changed", call)
					}
				}
				if _, err := os.Stat(filepath.Join(m.updateJournalDir(), xrayCoreMarkerFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published format despite foreign owner", err)
				}
				views, err := m.List(ctx, false)
				if err != nil {
					t.Fatal(err)
				}
				view := componentView(t, views, "xray")
				if view.CanInstall || view.CanUpdate || view.CanRemove || view.LifecycleBlockReason == "" {
					t.Fatal("UI does not respect owner", view)
				}
				if test.installed != "" && (view.Package != "xray" || !view.Installed) {
					t.Fatal("lost legacy inventory", view)
				}
				if test.script {
					if b, e := os.ReadFile(path); e != nil || string(b) != "ENABLED=yes\n" {
						t.Fatal("modified init script", e)
					}
				}
				return
			}
			count := 0
			for _, call := range r.calls {
				if len(call) > 1 && call[1] == "install" {
					count++
					if len(call) != 3 || call[2] != "xray-core" {
						t.Fatal(call)
					}
				}
			}
			if count != 1 {
				t.Fatal("expected one core install", r.calls)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unexpected init", err)
			}
			b, err := os.ReadFile(filepath.Join(m.StateDir, "receipts", "xray.json"))
			if err != nil || !strings.Contains(string(b), `"package": "xray-core"`) {
				t.Fatal(string(b), err)
			}
			if v, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || v != 7 {
				t.Fatal("fresh install reader", v, err)
			}
		})
	}
}

func TestXrayWriteRequiresCompatibleRollbackController(t *testing.T) {
	r := &fakeRunner{}
	m := &Manager{Opkg: "opkg", StateDir: t.TempDir(), Runner: r, AdmitXrayCoreWrite: func(context.Context) (context.Context, func(), error) { return nil, nil, ErrRecoveryAuthority }}
	if _, err := m.Apply(context.Background(), "xray"); !errors.Is(err, ErrRecoveryAuthority) {
		t.Fatal(err)
	}
	if _, err := m.Remove(context.Background(), "xray"); !errors.Is(err, ErrRecoveryAuthority) {
		t.Fatal(err)
	}
	if _, err := m.ManagedUpdate(context.Background(), "xray", allowRecovery); !errors.Is(err, ErrRecoveryAuthority) {
		t.Fatal(err)
	}
	if len(r.calls) != 0 {
		t.Fatal("called opkg before admission", r.calls)
	}
}

func TestXrayJournalPackageMatchesVersionAndArtifact(t *testing.T) {
	for _, version := range []int{1, 2, 7} {
		for _, pkg := range []string{"xray", "xray-core"} {
			doc := updateJournal{ManagedUpdateState: ManagedUpdateState{Component: "xray", SchemaVersion: version, TransactionID: strings.Repeat("a", 32), UpdatedAt: "2026-11-24T10:00:00Z", BeforeVersion: "26.3.27-1", Phase: UpdatePrepared}, Package: pkg, PackageSHA256: strings.Repeat("0", 64), PackageFile: pkg + "_26.3.27-1_aarch64-3.10.ipk"}
			want := version == 7 && pkg == "xray-core" || version < 7 && pkg == "xray"
			if err := validateUpdateJournal(doc); (err == nil) != want {
				t.Fatal(version, pkg, err)
			}
			doc.PackageFile = "foreign_26.3.27-1_aarch64-3.10.ipk"
			if validateUpdateJournal(doc) == nil {
				t.Fatal("accepted wrong snapshot", version, pkg)
			}
		}
	}
}

func TestXrayReceiptCannotVerifyDifferentOpkgIdentity(t *testing.T) {
	m := &Manager{StateDir: t.TempDir()}
	receipt := lifecycleReceipt{SchemaVersion: 1, Component: "xray", Package: "xray", Provider: "opkg", AfterVersion: "26.10.29-1", Action: "install"}
	if err := m.writeLifecycleReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	spec, _ := lookup("xray")
	view := View{Spec: spec, Installed: true, InstalledVersion: receipt.AfterVersion}
	m.attachLifecycleVerification(&view)
	if view.Verification == "verified" {
		t.Fatal("verified old receipt as new package")
	}
	view.Package = "xray"
	m.attachLifecycleVerification(&view)
	if view.Verification != "verified" {
		t.Fatal("lost old package receipt", view)
	}
	ctx := context.Background()
	if v, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || v != ComponentUpdateSchema {
		t.Fatal(v, err)
	}
	receipt.Package = "xray-core"
	if err := m.writeLifecycleReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err == nil {
		t.Fatal("core receipt accepted without format marker")
	}
	if err := os.MkdirAll(filepath.Join(m.updateJournalDir(), xrayCoreMarkerFile), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err == nil {
		t.Fatal("accepted marker directory")
	}
}

// The legacy rollback artifact is the metapackage and its config declarations.
// The clean installation uses the core package with a different artifact name.
type xrayUpdateRunner struct {
	*managedRunner
	pkg string
}

func (r *xrayUpdateRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) == 1 && args[0] == "list-installed" {
		return []byte("sing-box-go - 1.14.4-2\n" + r.pkg + " - " + r.installed + "\n"), nil
	}
	if len(args) == 1 && args[0] == "list" {
		return []byte(r.pkg + " - " + r.available + "\n"), nil
	}
	return r.managedRunner.Run(ctx, name, args...)
}

func TestXrayLegacyAndCorePendingRecovery(t *testing.T) {
	for _, pkg := range []string{"xray", "xray-core"} {
		t.Run(pkg, func(t *testing.T) {
			ctx := context.Background()
			m, r, conf := managedFixture(t)
			m.Runner = &xrayUpdateRunner{r, pkg}
			m.InitDir = t.TempDir()
			m.AdmitXrayCoreWrite = admitTestXray
			r.installed, r.available = "26.3.27-1", "26.10.29-1"
			if err := os.WriteFile(filepath.Join(m.InfoDir, pkg+".conffiles"), []byte(conf+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			spec, _ := lookup("xray")
			spec.Package = pkg
			if err := os.MkdirAll(m.rollbackDir(), 0700); err != nil {
				t.Fatal(err)
			}
			rollback := filepath.Join(m.rollbackDir(), pkg+"_"+r.installed+"_aarch64-3.10.ipk")
			if err := os.WriteFile(rollback, []byte("sealed xray fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			var transaction string
			if pkg == "xray-core" {
				result, err := m.ManagedUpdate(ctx, "xray", allowRecovery)
				if err != nil || !result.PendingLiveAcceptance {
					t.Fatalf("upgrade: %+v %v", result, err)
				}
				transaction = result.TransactionID
			} else {
				// Produce the exact U1/U2 legacy package/receipt shape without
				// invoking a newly-authorized upgrade on the foreign metapackage.
				tx, err := m.lockUpdateJournal()
				if err != nil {
					t.Fatal(err)
				}
				configs, err := m.snapshotConffiles(spec)
				if err != nil {
					t.Fatal(err)
				}
				if err = tx.prepare(spec, r.installed, rollback, configs); err != nil {
					t.Fatal(err)
				}
				r.installed = r.available
				tx.doc.AfterVersion = r.installed
				if err = tx.captureCandidateConfig(spec); err != nil {
					t.Fatal(err)
				}
				if err = tx.phase(UpdateAwaitingLive); err != nil {
					t.Fatal(err)
				}
				transaction = tx.doc.TransactionID
				tx.close()
				m.AdmitXrayCoreWrite = nil
			}
			state, pending, err := m.PendingManagedUpdate()
			if err != nil || !pending || state.TransactionID != transaction {
				t.Fatal(state, err)
			}
			want := ComponentUpdateSchema
			if pkg == "xray-core" {
				want = XrayCorePackageReadVersion
			}
			if state.SchemaVersion != want {
				t.Fatalf("wrong schema %d", state.SchemaVersion)
			}
			request := ManagedRecoveryRequest{Component: "xray", TransactionID: transaction, Action: "accept-installed-idle", QuiescenceCheck: allowRecovery, InactivityCheck: allowRecovery}
			result, err := m.RecoverManagedUpdate(ctx, request, allowRecovery, nil)
			if err != nil || !result.OK {
				t.Fatal("recovery", result, err)
			}
			data, err := os.ReadFile(filepath.Join(m.StateDir, "receipts", "xray.json"))
			if err != nil || !strings.Contains(string(data), "\"package\": \""+pkg+"\"") {
				t.Fatal(string(data), err)
			}
			if version, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || version != want {
				t.Fatal(version, err)
			}
		})
	}
}
