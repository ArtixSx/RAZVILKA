package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
)

func TestComponentRuntimeInventoryDoesNotInventPackageOwnership(t *testing.T) {
	for _, tc := range []struct {
		id, provider, state string
		installed, running  bool
	}{
		{"amneziawg", "platform", "platform-installed", false, false},
		{"amneziawg", "platform", "platform-active", false, true},
		{"xray", "opkg", "runtime-installed", false, false},
		{"sing-box", "opkg", "installed", true, false},
	} {
		t.Run(tc.state+tc.id, func(t *testing.T) {
			view := components.View{Spec: components.Spec{ID: tc.id, Provider: tc.provider}, State: "installed", Installed: tc.installed, CanInstall: !tc.installed, CanUpdate: tc.installed, CanRemove: tc.installed, AvailableVersion: "99.0", UpdateAvailable: true}
			if tc.installed {
				view.InstalledVersion, view.InstalledVersionSource = "1.13.3-2", "opkg"
			}
			views := []components.View{view}
			mergeComponentRuntimes(views, []engine.Status{{ID: tc.id, Installed: true, Version: "1.13.3", Running: tc.running, Configured: true}})
			v := views[0]
			if !v.Installed || !v.Configured || v.Running != tc.running || v.State != tc.state || v.RuntimeVersion != "1.13.3" {
				t.Fatal(v)
			}
			if !tc.installed && (v.CanInstall || v.CanUpdate || v.CanRemove || v.UpdateAvailable || v.LifecycleBlockReason == "" || v.InstalledVersionSource != "runtime") {
				t.Fatal(v)
			}
			if tc.installed && (v.InstalledVersion != "1.13.3-2" || v.InstalledVersionSource != "opkg") {
				t.Fatal("package and executable version were conflated", v)
			}
		})
	}
}

func TestComponentRuntimeUnknownVersionAndExternalOwnerRemainHonest(t *testing.T) {
	views := []components.View{{Spec: components.Spec{ID: "amneziawg", Provider: "platform"}}, {Spec: components.Spec{ID: "nfqws2", Provider: "opkg"}, Installed: true, InstalledVersion: "2.0", CanRemove: true, CanUpdate: true}}
	mergeComponentRuntimes(views, []engine.Status{{ID: "amneziawg", Installed: true}, {ID: "nfqws2", Installed: true, External: true}})
	if !views[0].Installed || views[0].InstalledVersion != "" || views[0].RuntimeVersion != "" {
		t.Fatal(views[0])
	}
	if views[1].CanRemove || views[1].CanUpdate || !views[1].ExternalOwner || views[1].State != "external-installed" {
		t.Fatal(views[1])
	}
}

func TestComponentPlansRejectUnmanagedRuntimeAndDependency(t *testing.T) {
	for _, action := range []string{"install", "update", "remove"} {
		p := components.Plan{Component: "xray", Action: action, Ready: true}
		enrichComponentRuntimePlan(&p, []engine.Status{{ID: "xray", Installed: true}})
		if p.Ready || !hasComponentBlocker(p, "UNMANAGED_RUNTIME") || !p.Installed {
			t.Fatal(p)
		}
	}
	p := components.Plan{Component: "usque", Action: "install", Ready: true, Dependencies: []components.DependencyState{{ID: "sing-box", Installed: false}}}
	enrichComponentRuntimePlan(&p, []engine.Status{{ID: "sing-box", Installed: true}})
	if p.Ready || !hasComponentBlocker(p, "UNMANAGED_DEPENDENCY") {
		t.Fatal(p)
	}
	// An already packaged/running shared core is reused without modification.
	p = components.Plan{Component: "usque", Action: "install", Ready: true, Dependencies: []components.DependencyState{{ID: "sing-box", Installed: true}}}
	enrichComponentRuntimePlan(&p, []engine.Status{{ID: "sing-box", Installed: true, Running: true}})
	if !p.Ready {
		t.Fatal(p)
	}
}

func TestComponentSidecarProtectionIncludesDesiredAppliedAndResolvedAuto(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for id, route := range map[string]string{"applied-xray": "xray:remote", "automatic": "auto"} {
		if err := store.UpdateService(id, config.ServiceState{Enabled: true, Route: route}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("applied-xray", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("desired-warp", config.ServiceState{Enabled: true, Mode: "warp"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("disabled", config.ServiceState{Enabled: false, Route: "usque"}); err != nil {
		t.Fatal(err)
	}
	dp := dataplane.New(t.TempDir())
	if err := dp.Record(dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "component-test", Digest: "component-test", State: "committed", Routes: []dataplane.Route{{ServiceID: "automatic", Selected: "auto", Resolved: "usque"}}}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Dataplane: dp}
	desired, applied := a.componentServiceReferences("sing-box")
	if !reflect.DeepEqual(desired, []string{"automatic", "desired-warp"}) || !reflect.DeepEqual(applied, []string{"applied-xray", "automatic"}) {
		t.Fatal(desired, applied)
	}
	for _, action := range []string{"update", "remove"} {
		p := components.Plan{Component: "sing-box", Action: action, Ready: true, Installed: true}
		a.enrichComponentPlan(&p)
		if p.Ready || !hasComponentBlocker(p, "SERVICE_DEPENDENCY") {
			t.Fatal(p)
		}
		blocker := a.componentRuntimeBlocker("sing-box", action)
		if blocker == nil || blocker["code"] != "SERVICE_DEPENDENCY" {
			t.Fatal(blocker)
		}
	}
	if desired, applied := a.componentServiceReferences("nfqws2"); len(desired) != 0 || len(applied) != 0 {
		t.Fatal(desired, applied)
	}
}

func hasComponentBlocker(p components.Plan, code string) bool {
	for _, issue := range p.Blockers {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestComponentMutationFailsClosedWhenCommittedStateUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "latest-committed-plan.json"), []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &App{Dataplane: dataplane.New(dir)}
	for _, action := range []string{"update", "remove"} {
		p := components.Plan{Component: "sing-box", Action: action, Installed: true, Ready: true}
		a.enrichComponentPlan(&p)
		if p.Ready || !hasComponentBlocker(p, "RUNTIME_STATE_UNKNOWN") {
			t.Fatal(p)
		}
	}
}

type componentInventoryRunner struct{ calls []string }

func (r *componentInventoryRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	r.calls = append(r.calls, command)
	switch command {
	case "list-installed":
		return []byte("sing-box-go - 1.13.3-2 - installed\n"), nil
	case "list":
		return []byte("sing-box-go - 1.14.0-1 - available\n"), nil
	case "update":
		return []byte("wget: not an http or ftp url: https://example.com"), errors.New("fixture offline")
	}
	return nil, errors.New("unexpected mutation")
}

func TestComponentRefreshReturnsInstalledArrayWithSourceFailure(t *testing.T) {
	runner := &componentInventoryRunner{}
	m := &components.Manager{Opkg: "opkg", Runner: runner, RepoDir: t.TempDir(), BinDir: t.TempDir(), Client: &http.Client{Transport: sourceFixtureTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline fixture") })}}
	a := &App{Components: m}
	r := httptest.NewRecorder()
	a.componentList(r, httptest.NewRequest(http.MethodGet, "/api/v1/components?refresh=true", nil))
	if r.Code != http.StatusOK {
		t.Fatal(r.Code, r.Body.String())
	}
	var views []components.View
	if err := json.Unmarshal(r.Body.Bytes(), &views); err != nil {
		t.Fatal("array contract changed", err)
	}
	for _, v := range views {
		if v.ID != "sing-box" {
			continue
		}
		if !v.Installed || v.InstalledVersion != "1.13.3-2" || !v.CatalogStale || v.CanUpdate || !v.CanRemove || !strings.Contains(v.UpdateCheckError, "wget-ssl") {
			t.Fatal(v)
		}
		return
	}
	t.Fatal("installed core disappeared")
}

func TestComponentMaintenanceDoesNotCompleteOnPartialCatalogFailure(t *testing.T) {
	runner := &componentInventoryRunner{}
	client := &http.Client{Transport: sourceFixtureTransport(func(*http.Request) (*http.Response, error) {
		body := `{"tag_name":"v2.2.32","assets":[{"name":"wgcf_2.2.32_linux_arm64","browser_download_url":"https://github.com/ViRb3/wgcf/releases/download/v2.2.32/wgcf_2.2.32_linux_arm64"},{"name":"checksums.txt","browser_download_url":"https://github.com/ViRb3/wgcf/releases/download/v2.2.32/checksums.txt"}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	a := &App{Components: &components.Manager{Opkg: "opkg", Runner: runner, RepoDir: t.TempDir(), BinDir: t.TempDir(), Client: client, Arch: "arm64"}}
	done, pending, message := a.runMaintenanceCheck(context.Background(), "components", autonomy.Window{}, false)
	if done || pending || message == "" {
		t.Fatal(done, pending, message)
	}
	for _, command := range runner.calls {
		if strings.HasPrefix(command, "install") || strings.HasPrefix(command, "upgrade") || strings.HasPrefix(command, "remove") {
			t.Fatal("maintenance mutated packages", command)
		}
	}
}
