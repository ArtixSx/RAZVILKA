package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

type autopilotEnginePackage struct {
	initDir    string
	name       string
	installed  bool
	commands   []string
	installErr error
	unverified bool
	observe    func(string)
}

func TestAutonomyTunnelPrerequisiteSeparatesRuntimeAndProfile(t *testing.T) {
	for _, test := range []struct {
		option routecatalog.Option
		staged bool
		want   string
	}{
		{option: routecatalog.Option{ID: "usque"}, want: "компонент недоступен"},
		{option: routecatalog.Option{ID: "usque", Installed: true}, want: "сессия MASQUE"},
		{option: routecatalog.Option{ID: "warp-wg", Installed: true}, want: "профиль WARP"},
		{option: routecatalog.Option{ID: "warp-wg", Installed: true, Configured: true}, staged: true, want: "черновик сохранён"},
		{option: routecatalog.Option{ID: "warp-wg", Installed: true, Configured: true}, want: "туннель сейчас не работает"},
	} {
		if diagnostic := autonomyTunnelPrerequisite(test.option, test.staged); !strings.Contains(diagnostic, test.want) {
			t.Fatalf("diagnostic %q does not describe %q", diagnostic, test.want)
		}
	}
	a := &App{}
	a.nodeReviews.options = func() []routecatalog.Option {
		t.Fatal("blocked domain route inspected tunnel prerequisites")
		return nil
	}
	p := autonomy.Default()
	p.PreferredRoutes = []string{"warp-wg", "usque", "wireguard", "amneziawg"}
	if message := a.autonomyMissingTunnelPrerequisite(p, config.Config{}, catalog.Service{ID: "test", Domains: []string{"example.org"}}); message != "" {
		t.Fatalf("ineligible tunnel produced a preparation diagnostic: %q", message)
	}
}

func (p *autopilotEnginePackage) Run(_ context.Context, binary string, args ...string) ([]byte, error) {
	if binary != "fixture-opkg" {
		return nil, errors.New("unexpected package manager")
	}
	command := strings.Join(args, " ")
	p.commands = append(p.commands, command)
	if p.observe != nil {
		p.observe(command)
	}
	packageName := p.name
	if packageName == "" {
		packageName = "sing-box-go"
	}
	switch command {
	case "list-installed":
		if !p.installed {
			return nil, nil
		}
		fallthrough
	case "list":
		return []byte(packageName + " - 1.13.3-2 - fixture package\n"), nil
	case "install wireguard-tools":
		if p.name != "wireguard-tools" || p.installErr != nil {
			return nil, errors.Join(errors.New("fixture WireGuard package install refused"), p.installErr)
		}
		p.installed = !p.unverified
		return nil, nil
	case "install sing-box-go":
		body := `#!/bin/sh
ENABLED=yes
PROCS=sing-box
ARGS="run -D /opt/var/lib/$PROCS -C /opt/etc/$PROCS"
PREARGS=""
DESC=$PROCS
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
. /opt/etc/init.d/rc.func
`
		if err := os.WriteFile(filepath.Join(p.initDir, "S99sing-box"), []byte(body), 0755); err != nil {
			return nil, err
		}
		p.installed = true
		return nil, nil
	default:
		return nil, errors.New("unexpected opkg action")
	}
}

func TestAutonomyPreparesMissingNodeEngineThenApplies(t *testing.T) {
	a, ids, adapter := autonomousIntegrationFixture(t)
	pkg := &autopilotEnginePackage{initDir: t.TempDir()}
	a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, InitDir: pkg.initDir, StateDir: t.TempDir(), BinDir: t.TempDir(), RepoDir: t.TempDir()}
	available := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		if pkg.installed {
			return available()
		}
		return []routecatalog.Option{{ID: "direct", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box"}}
	}
	a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
		return true, false, "fixture"
	}
	p := a.autonomyPolicy()
	p.PreferredRoutes = []string{"sing-box"}
	now := time.Now().UTC()
	allow := true
	p.InstallMissingComponents = &allow
	p.Components.Mode = "off"
	p.Components.Start = now.Add(time.Hour).Format("15:04")
	p.Components.End = now.Add(2 * time.Hour).Format("15:04")
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
	if w.Code != http.StatusOK {
		t.Fatalf("enable component preparation: %d %s", w.Code, w.Body.String())
	}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if !pkg.installed {
			t.Fatal("checked node before the missing package was installed")
		}
		checked = append(checked, request.NodeID)
		return d10Result(request, "sing-box", true), nil
	})
	a.autonomyRound(context.Background(), time.Now())
	runtime := autonomyTestState(a)
	if runtime.State != "applied" || !slices.Equal(checked, ids[:1]) || !slices.Contains(adapter.calls, "commit") {
		t.Fatalf("round did not continue to first usable Apply: runtime=%+v checked=%v package=%v transaction=%v", runtime, checked, pkg.commands, adapter.calls)
	}
}

func TestAutonomyPreparesCandidateSpecificAlternate(t *testing.T) {
	for _, mode := range []string{"allowed", "denied", "window"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			a, old, adapter := autonomousIntegrationFixture(t)
			for _, id := range old {
				if _, err := a.Nodes.SetDisabled(ctx, id, true, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			source := nodestore.Source{ID: "manual", Kind: "manual"}
			snapshot, err := a.Nodes.Import(ctx, source, "hysteria2://fixture@two.example:8443?sni=front.example", time.Now(), time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			candidate := ""
			for _, node := range snapshot.Nodes {
				if strings.EqualFold(node.Protocol, "hysteria2") {
					candidate = node.ID
				}
			}
			if candidate == "" {
				t.Fatal("Hysteria2 profile was not imported")
			}
			pkg := &autopilotEnginePackage{initDir: t.TempDir()}
			a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, InitDir: pkg.initDir, StateDir: t.TempDir(), BinDir: t.TempDir(), RepoDir: t.TempDir()}
			a.nodeReviews.options = func() []routecatalog.Option {
				out := []routecatalog.Option{{ID: "direct", Installed: true, Selectable: true}, {ID: "xray", Installed: true, Configured: true, Selectable: true}, {ID: "sing-box", Installed: pkg.installed, Configured: pkg.installed, Selectable: pkg.installed}}
				if pkg.installed {
					out = append(out, routecatalog.Option{ID: "sing-box:" + candidate, Installed: true, Configured: true, Selectable: true, Services: []string{"my-independent-site"}})
				}
				return out
			}
			p := a.autonomyPolicy()
			p.PreferredRoutes = []string{"xray", "sing-box"}
			p.Protocols = []string{"hysteria2"}
			allow := mode == "allowed"
			p.InstallMissingComponents = &allow
			if mode == "window" {
				p.Timezone = "UTC"
				p.InstallMissingComponents = nil
				p.Components.Mode = "install"
				now := time.Now().UTC()
				p.Components.Start = now.Add(time.Hour).Format("15:04")
				p.Components.End = now.Add(2 * time.Hour).Format("15:04")
			}
			a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
				return true, false, "fixture"
			}
			w := httptest.NewRecorder()
			a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
			if w.Code != http.StatusOK {
				t.Fatalf("save policy: %d %s", w.Code, w.Body.String())
			}
			a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				t.Fatal("incompatible Xray was used to check Hysteria2")
				return dataplane.NodeCheckResult{}, nil
			})}
			checked := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				if !pkg.installed || request.NodeID != candidate {
					t.Fatalf("unprepared or different candidate was checked: %s", request.NodeID)
				}
				checked++
				return d10Result(request, "sing-box", true), nil
			})
			a.autonomyRound(ctx, time.Now())
			state := autonomyTestState(a)
			if allow {
				if state.State != "applied" || checked != 1 || !slices.Contains(adapter.calls, "commit") || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+candidate {
					t.Fatalf("alternate did not install, check and apply: runtime=%+v installer=%v manager=%v", state, pkg.commands, adapter.calls)
				}
				return
			}
			want := "component-unavailable"
			if mode == "window" {
				want = "component-window"
			}
			if state.State != want || checked != 0 || len(pkg.commands) != 0 || len(adapter.calls) != 0 || len(state.CandidateFailures) != 0 {
				t.Fatalf("unavailable alternate was probed or applied: runtime=%+v installer=%v manager=%v", state, pkg.commands, adapter.calls)
			}
		})
	}
}

func TestAutonomyMissingCandidateExecutorDoesNotBlockOtherCandidate(t *testing.T) {
	ctx := context.Background()
	a, ids, adapter := autonomousIntegrationFixture(t)
	snapshot, err := a.Nodes.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, autonomyXHTTPURI, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	missing := ""
	for _, n := range snapshot.Nodes {
		if n.Transport == "xhttp" {
			missing = n.ID
		}
	}
	if missing == "" {
		t.Fatal("XHTTP candidate missing")
	}
	p := a.autonomyPolicy()
	p.PreferredRoutes = []string{"sing-box", "xray"}
	p.CandidatesPerRound = 2
	deny := false
	p.InstallMissingComponents = &deny
	w := httptest.NewRecorder()
	a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
	if w.Code != http.StatusOK {
		t.Fatalf("save policy: %d %s", w.Code, w.Body.String())
	}
	a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		t.Fatal("Xray was started despite the installation refusal")
		return dataplane.NodeCheckResult{}, nil
	})}
	var checked []string
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		return d10Result(req, "sing-box", true), nil
	})
	// Resume a saved traversal in which the unavailable profile precedes a
	// usable peer. The ordinary worker still reviews permission and resources.
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p = a.autonomyPolicy()
	spec := a.autonomy.doc.Services["my-independent-site"]
	a.autonomyRuntime(a.autonomyPolicy().Revision, spec.ID, autonomy.Runtime{State: "searching", Search: &autonomy.Traversal{
		Version: autonomyTraversalVersion(p, spec, "sing-box", profile), Ordered: []string{missing, ids[0]},
	}})
	a.autonomyRound(ctx, time.Now())
	state := autonomyTestState(a)
	if state.State != "applied" || state.Search == nil || state.Search.Cursor != 2 || !slices.Equal(checked, ids[:1]) || !slices.Contains(adapter.calls, "commit") || len(state.CandidateFailures) != 0 {
		t.Fatalf("unavailable executor stopped or penalized the traversal: runtime=%+v checks=%v manager=%v", state, checked, adapter.calls)
	}
}

func TestAutonomyMissingDaytimeEngineKeepsSearchingAvailableRoutes(t *testing.T) {
	for _, halted := range []bool{false, true} {
		name := "continue-ready-route"
		if halted {
			name = "keep-unverified-apply-fence"
		}
		t.Run(name, func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			sourcePriorityImport(t, a, ids[0], "priority", "")
			sourcePriorityPolicy(t, a, 1)
			var probes []string
			sourcePriorityProber(a, &probes)
			options := a.nodeReviews.options
			a.nodeReviews.options = func() []routecatalog.Option {
				return slices.DeleteFunc(options(), func(option routecatalog.Option) bool { return option.ID == "sing-box" })
			}
			pkg := &autopilotEnginePackage{initDir: t.TempDir()}
			a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, InitDir: pkg.initDir, StateDir: t.TempDir()}
			a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
				return true, false, "fixture"
			}
			now := time.Now().UTC()
			p := a.autonomyPolicy()
			p.PreferredRoutes = []string{"sing-box", "warp-wg"}
			p.Components.Mode = "install"
			p.Components.Start, p.Components.End = now.Add(2*time.Hour).Format("15:04"), now.Add(3*time.Hour).Format("15:04")
			w := httptest.NewRecorder()
			a.autonomyAPI(w, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY"}))
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			p = a.autonomyPolicy()
			const serviceID = "my-independent-site"
			spec := a.autonomy.doc.Services[serviceID]
			runtime := autonomyTestState(a)
			profile, err := a.freshNetworkProfile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			runtime.Search = &autonomy.Traversal{Version: autonomyTraversalVersion(p, spec, "sing-box", profile), Ordered: ids, Cursor: 1, Halted: halted}
			a.autonomyRuntime(a.autonomyPolicy().Revision, serviceID, runtime)
			a.NodeChecker = jobNodeChecker(func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				t.Fatal("the absent engine was used outside the installation window")
				return dataplane.NodeCheckResult{}, nil
			})
			a.autonomyRound(context.Background(), now)
			result := autonomyTestState(a)
			wantProbes := []string{"warp-wg"}
			if halted {
				wantProbes = nil
			}
			if !slices.Equal(probes, wantProbes) || len(pkg.commands) != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(runtime.Search, result.Search) {
				t.Fatalf("unexpected probes=%v packages=%v apply=%v search=%+v", probes, pkg.commands, adapter.calls, result.Search)
			}
			nextWindow := autonomy.NextWindow(p.Components, p.Timezone, now)
			if result.State != "component-window" || !result.NextCheck.Before(nextWindow) || !strings.Contains(result.Message, nextWindow.Format("15:04")) {
				t.Fatalf("window or next service check was lost: window=%v runtime=%+v", nextWindow, result)
			}
		})
	}
}
