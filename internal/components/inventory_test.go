package components

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type inventoryRunner struct {
	*fakeRunner
	fail   string
	output string
}

func (r *inventoryRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if strings.Join(args, " ") == r.fail {
		return []byte(r.output), errors.New("fixture failure")
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

type inventoryTransport func(*http.Request) (*http.Response, error)

func (f inventoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func offlineReleases() *http.Client {
	return &http.Client{Transport: inventoryTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline test; no external requests")
	})}
}

func componentView(t *testing.T, views []View, id string) View {
	t.Helper()
	for _, view := range views {
		if view.ID == id {
			return view
		}
	}
	t.Fatalf("component %s missing", id)
	return View{}
}

func TestCatalogFailureKeepsInstalledFactsAndRequiresSuccessfulRefresh(t *testing.T) {
	r := &inventoryRunner{fakeRunner: &fakeRunner{output: map[string]string{
		"list-installed": "sing-box-go - 1.13.3-2 - existing\n",
		"list":           "sing-box-go - 1.14.0-1 - available\nnfqws2-keenetic - 2.0 - available\n",
		"update":         "ok",
	}}}
	m := &Manager{Opkg: "opkg", Runner: r, RepoDir: t.TempDir(), InitDir: t.TempDir(), BinDir: t.TempDir(), Client: offlineReleases()}
	views, err := m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	before := componentView(t, views, "sing-box")
	if before.CheckedAt == "" || !before.CanUpdate || before.InstalledVersionSource != "opkg" || before.AvailableVersionSource != "opkg" {
		t.Fatal(before)
	}
	r.fail, r.output = "update", "wget: not an http or ftp url: https://private.invalid/?secret=must-not-escape"
	views, err = m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, refresh := range []bool{false, false} {
		v := componentView(t, views, "sing-box")
		if !v.Installed || v.InstalledVersion != "1.13.3-2" || !v.CatalogStale || v.CanUpdate || v.CanInstall || !v.CanRemove || v.CheckedAt != before.CheckedAt || !strings.Contains(v.UpdateCheckError, "wget-ssl") || strings.Contains(v.UpdateCheckError, "secret") {
			t.Fatal(v)
		}
		if v := componentView(t, views, "nfqws2"); v.CanInstall {
			t.Fatal(v)
		}
		views, err = m.List(context.Background(), refresh)
		if err != nil {
			t.Fatal(err)
		}
	}
	plan, err := m.Plan(context.Background(), "nfqws2", "install", false)
	if err != nil || plan.Ready || !hasInventoryIssue(plan, "CATALOG_STALE") {
		t.Fatal(plan, err)
	}
	if _, err := m.Apply(context.Background(), "nfqws2"); err == nil {
		t.Fatal("Apply bypassed a failed source refresh")
	}
	r.fail = ""
	views, err = m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	v := componentView(t, views, "sing-box")
	if v.CatalogStale || v.UpdateCheckError != "" || !v.CanUpdate || v.CheckedAt == before.CheckedAt {
		t.Fatal(v)
	}
}

func hasInventoryIssue(p Plan, code string) bool {
	for _, issue := range p.Blockers {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestRuntimeDependencyGraphMatchesManagedAdapters(t *testing.T) {
	for _, route := range []string{"usque", "warp", "warp-masque", "xray", "xray:profile", "sing-box:node-1"} {
		if !RuntimeUses(route, "sing-box") {
			t.Fatalf("missing sidecar dependency for %s", route)
		}
	}
	for _, route := range []string{"direct", "nfqws2", "warp-wg", "auto", "xray-other"} {
		if RuntimeUses(route, "sing-box") {
			t.Fatalf("invented sidecar dependency for %s", route)
		}
	}
	if RuntimeUses("warp-wg", "wgcf") {
		t.Fatal("profile generator is not a forwarding runtime")
	}
	xray, _ := lookup("xray")
	if !reflect.DeepEqual(xray.Dependencies, []string{"sing-box"}) || !reflect.DeepEqual(xray.RuntimeDependencies, []string{"sing-box"}) {
		t.Fatal(xray)
	}
}

func TestParentInstallNeverUpgradesExistingSharedCore(t *testing.T) {
	for _, parent := range []string{"usque", "xray"} {
		t.Run(parent, func(t *testing.T) {
			r := &fakeRunner{output: map[string]string{"list-installed": "sing-box-go - 1.13.3-2 - shared\n", "install": "ok", "update": "ok"}}
			m := &Manager{Opkg: "opkg", Runner: r, RepoDir: t.TempDir(), StateDir: t.TempDir()}
			result, err := m.Apply(context.Background(), parent)
			if err != nil || !result.OK {
				t.Fatal(result, err)
			}
			for _, call := range r.calls {
				if len(call) > 2 && call[2] == "sing-box-go" {
					t.Fatal("shared core was mutated", call)
				}
			}
			if got := parsePackageVersions(r.output["list-installed"])["sing-box-go"]; got != "1.13.3-2" {
				t.Fatal(got)
			}
		})
	}
}

func TestFreshParentInstallDisablesNewSharedCoreAutostart(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"install": "ok", "update": "ok"}}
	dir := t.TempDir()
	r.afterInstall = func() error {
		call := r.calls[len(r.calls)-1]
		if len(call) > 2 && call[2] == "sing-box-go" {
			return os.WriteFile(filepath.Join(dir, singBoxInitName), []byte(singBoxInitFixture), 0700)
		}
		return nil
	}
	m := &Manager{Opkg: "opkg", Runner: r, RepoDir: t.TempDir(), InitDir: dir, StateDir: t.TempDir()}
	if result, err := m.Apply(context.Background(), "usque"); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, singBoxInitName))
	if err != nil || strings.Contains(string(data), "ENABLED=yes") || !strings.Contains(string(data), "ENABLED=no") {
		t.Fatal(string(data), err)
	}
}

func TestReleaseFailureKeepsCachedVersionAndSuccessfulCheckTimestamp(t *testing.T) {
	fail := false
	client := &http.Client{Transport: inventoryTransport(func(*http.Request) (*http.Response, error) {
		if fail {
			return nil, errors.New("network failure")
		}
		body := `{"tag_name":"v2.2.32","assets":[{"name":"wgcf_2.2.32_linux_arm64","browser_download_url":"https://github.com/ViRb3/wgcf/releases/download/v2.2.32/wgcf_2.2.32_linux_arm64"},{"name":"checksums.txt","browser_download_url":"https://github.com/ViRb3/wgcf/releases/download/v2.2.32/checksums.txt"}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	m := &Manager{BinDir: t.TempDir(), Client: client, Arch: "arm64"}
	views, err := m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	before := componentView(t, views, "wgcf")
	if before.CheckedAt == "" || !before.CanInstall {
		t.Fatal(before)
	}
	fail = true
	for _, refresh := range []bool{true, false} {
		views, err = m.List(context.Background(), refresh)
		if err != nil {
			t.Fatal(err)
		}
		v := componentView(t, views, "wgcf")
		if v.AvailableVersion != before.AvailableVersion || v.CheckedAt != before.CheckedAt || !v.CatalogStale || v.UpdateCheckError == "" || v.CanInstall || v.CanUpdate {
			t.Fatal(v)
		}
	}
}

func TestOwnedReleaseStillRemovableWhenLatestCheckFails(t *testing.T) {
	m := &Manager{BinDir: t.TempDir(), Client: offlineReleases(), StateDir: t.TempDir()}
	target := filepath.Join(m.BinDir, "wgcf")
	binary := []byte("receipt-owned fixture; never run")
	if err := os.WriteFile(target, binary, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, "2.2.32", binary); err != nil {
		t.Fatal(err)
	}
	views, err := m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	v := componentView(t, views, "wgcf")
	if !v.Installed || !v.CanRemove || v.CanInstall || v.CanUpdate || !v.CatalogStale || v.InstalledVersionSource != "receipt" {
		t.Fatal(v)
	}
	p, err := m.Plan(context.Background(), "wgcf", "remove", false)
	if err != nil || !p.Ready {
		t.Fatal(p, err)
	}
}

func TestManualReleaseFileIsVisibleAndCannotBeReplaced(t *testing.T) {
	m := &Manager{BinDir: t.TempDir(), Client: offlineReleases()}
	target := filepath.Join(m.BinDir, "wgcf")
	binary := []byte("manually installed fixture; not executable")
	if err := os.WriteFile(target, binary, 0600); err != nil {
		t.Fatal(err)
	}
	views, err := m.List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	v := componentView(t, views, "wgcf")
	if !v.Installed || v.CanInstall || v.CanRemove || v.CanUpdate || v.InstalledVersion != "" || v.InstalledVersionSource != "runtime" {
		t.Fatal(v)
	}
	if _, err := m.Apply(context.Background(), "wgcf"); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatal(err)
	}
	if _, err := m.Remove(context.Background(), "wgcf"); err == nil {
		t.Fatal("manual file removable")
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(binary) {
		t.Fatal("manual binary changed", err)
	}
}

func TestParentPlanRejectsManualReleaseDependencyBeforeConfirmation(t *testing.T) {
	for _, action := range []string{"install", "update", "remove"} {
		for _, owned := range []bool{false, true} {
			name := action + "/manual-wgcf"
			if owned {
				name = action + "/receipt-wgcf"
			}
			t.Run(name, func(t *testing.T) {
				r := &fakeRunner{output: map[string]string{
					"list": "wireguard-tools - 2.0 - available\n",
				}}
				if action != "install" {
					r.output["list-installed"] = "wireguard-tools - 1.0 - installed\n"
				}
				m := &Manager{Opkg: "opkg", Runner: r, BinDir: t.TempDir(), Client: offlineReleases()}
				target := filepath.Join(m.BinDir, "wgcf")
				binary := []byte("fixture dependency; deliberately not executable")
				if err := os.WriteFile(target, binary, 0600); err != nil {
					t.Fatal(err)
				}
				if owned {
					if err := writeExternalReceipt(target, "2.2.32", binary); err != nil {
						t.Fatal(err)
					}
				}
				plan, err := m.Plan(context.Background(), "warp-wg", action, false)
				if err != nil {
					t.Fatal(err)
				}
				blocked := !owned && action != "remove"
				if plan.Ready == blocked || hasInventoryIssue(plan, "UNMANAGED_DEPENDENCY") != blocked {
					t.Fatalf("parent preflight did not match dependency ownership: %+v", plan)
				}
				if action != "remove" && !reflect.DeepEqual(plan.Dependencies, []DependencyState{{ID: "wgcf", Installed: true}}) {
					t.Fatal("installed fact was lost while enforcing ownership", plan.Dependencies)
				}
				for _, call := range r.calls {
					if len(call) < 2 || call[1] != "list" && call[1] != "list-installed" {
						t.Fatal("preflight mutated the package state", call)
					}
				}
				after, err := os.ReadFile(target)
				if err != nil || string(after) != string(binary) {
					t.Fatal("preflight changed dependency bytes", err)
				}
			})
		}
	}
}
