package app

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyUSQUEMissingComponentDoesNotStartVendorPackage(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		consent   bool
		installed bool
		reserve   bool
		state     string
		message   string
	}{
		{name: "absent", consent: true, state: "masque-component-unavailable", message: "запускает собственный туннель"},
		{name: "absent with authorized reserve", consent: true, reserve: true, state: "applied"},
		{name: "inventory ready without original owner", consent: true, reserve: true, installed: true, state: "applied"},
		{name: "installed without managed readiness", consent: true, installed: true, state: "masque-component-unavailable", message: "управляемый TUN"},
		{name: "no registration consent", state: "masque-consent-required", message: "отдельное согласие"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			a, ids, adapter := autonomousIntegrationFixture(t)
			s := setAutonomyUSQUEPolicy(t, a, scenario.consent)
			options := a.nodeReviews.options
			a.nodeReviews.options = func() []routecatalog.Option {
				return append(options(), routecatalog.Option{ID: "usque", Installed: scenario.installed, Ready: scenario.installed && scenario.reserve})
			}
			pkg := &autopilotEnginePackage{name: "usque-keenetic"}
			a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, StateDir: t.TempDir(), RepoDir: t.TempDir()}
			a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
				return true, false, "fixture"
			}
			allowInstall := true
			ctx := context.Background()
			a.autonomy.mu.Lock()
			a.autonomy.doc.Policy.InstallMissingComponents = &allowInstall
			if !scenario.reserve {
				a.autonomy.doc.Policy.PreferredRoutes = []string{"usque"}
				a.autonomy.doc.Policy.SourceIDs = nil
			}
			err := a.persistAutonomyLocked(ctx)
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if scenario.installed && scenario.reserve {
				a.TestLab = testlab.NewRunner()
				a.RouteProber = autonomyResourceRouteProber(func(_ context.Context, service catalog.Service, route string) testlab.Result {
					if route == "usque" {
						t.Error("generic route probe bypassed the owner's MASQUE checks")
					}
					return testlab.Result{ServiceID: service.ID, Route: route, Status: "not-ready"}
				})
			}
			var checked []string
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checked = append(checked, req.NodeID)
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(ctx, time.Now())
			runtime := autonomyTestState(a)
			if runtime.State != scenario.state || !strings.Contains(runtime.Message, scenario.message) || len(pkg.commands) != 0 {
				t.Fatalf("unexpected prerequisite or package call: state=%s, message=%q, commands=%v", runtime.State, runtime.Message, pkg.commands)
			}
			applied := a.Store.Get().AppliedServices[s.ID]
			if scenario.reserve {
				if selectedRoute(applied) != "sing-box:"+ids[0] || !slices.Equal(checked, ids[:1]) || !slices.Contains(adapter.calls, "commit") {
					t.Fatalf("missing USQUE blocked an allowed reserve: %+v, checks=%v, calls=%v", applied, checked, adapter.calls)
				}
			} else if applied.Enabled || len(checked) != 0 || len(adapter.calls) != 0 || runtime.NextCheck.IsZero() || len(runtime.Switches) != 0 {
				t.Fatal("waiting for the component consumed an attempt or changed the plan", runtime, adapter.calls)
			}
		})
	}
}

func TestAutonomyUSQUEBinaryPreparationUsesOwnedInstallerPolicy(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		windowOnly bool
		reserve    bool
	}{
		{name: "closed installation window", windowOnly: true},
		{name: "unsupported install root continues reserve", reserve: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			a, ids, adapter := autonomousIntegrationFixture(t)
			s := setAutonomyUSQUEPolicy(t, a, true)
			base := filepath.Dir(a.Dataplane.StateRoot)
			control := filepath.Join(base, "control")
			a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: control}
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
				t.Fatal(err)
			}
			if err := a.ConfigureDefaultConsent(filepath.Join(base, "config.json"), filepath.Join(base, "nodes")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.CloseDefaultConsent() })
			a.EngineConfigs = engineconfig.New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
			a.DataplaneHost = func() dataplane.HostState {
				return dataplane.HostState{IPCommand: true, TUN: true, SingBox: true}
			}
			if err := a.Dataplane.Register(&autonomyUSQUEApplyModel{}); err != nil {
				t.Fatal(err)
			}
			pkg := &autopilotEnginePackage{name: "usque-keenetic"}
			// A disposable component state root exercises the production
			// installer's early refusal. No package manager or download is used.
			a.Components = &components.Manager{Runner: pkg, StateDir: t.TempDir(), BinDir: t.TempDir()}
			a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
				return true, false, "fixture"
			}
			now := time.Now().UTC()
			start := now.Add(8 * time.Hour)
			a.autonomy.mu.Lock()
			p := &a.autonomy.doc.Policy
			allowInstall := true
			p.InstallMissingComponents = &allowInstall
			if scenario.windowOnly {
				p.InstallMissingComponents = nil
				p.Components = autonomy.Window{Mode: "install", Start: start.Format("15:04"), End: start.Add(time.Hour).Format("15:04"), Days: []int{0, 1, 2, 3, 4, 5, 6}}
				p.PreferredRoutes = []string{"usque"}
				p.SourceIDs = nil
			}
			err := a.persistAutonomyLocked(ctx)
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(ctx, now)
			runtime := autonomyTestState(a)
			last, err := a.Components.LastInstallAttempt("usque")
			if err != nil || len(pkg.commands) != 0 {
				t.Fatalf("binary install called opkg or lost attempt status: %v, commands=%v", err, pkg.commands)
			}
			applied := a.Store.Get().AppliedServices[s.ID]
			if scenario.windowOnly {
				if runtime.State != "component-window" || !runtime.NextCheck.Equal(start.Truncate(time.Minute)) ||
					!strings.Contains(runtime.Message, "Следующая попытка установки") || !last.IsZero() || applied.Enabled || len(adapter.calls) != 0 {
					t.Fatalf("closed window did not preserve the pending MASQUE setup: %+v, last=%v", runtime, last)
				}
			} else if scenario.reserve && (runtime.State != "applied" || last.IsZero() || selectedRoute(applied) != "sing-box:"+ids[0]) {
				t.Fatalf("unavailable owned installer blocked later VLESS: %+v, last=%v, route=%+v", runtime, last, applied)
			}
		})
	}
}

func TestAutonomyUSQUELocalPrerequisitesDoNotStartPackageHooks(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		host    dataplane.HostState
		boot    string
		message string
	}{
		{name: "missing ip", host: dataplane.HostState{TUN: true, SingBox: true}, message: "Команда ip"},
		{name: "missing TUN", host: dataplane.HostState{IPCommand: true, SingBox: true}, message: "/dev/net/tun"},
		{name: "missing managed Sing-box without compatible adapter", host: dataplane.HostState{IPCommand: true, TUN: true}, message: "пакета Entware"},
		{name: "preserves selected backend", host: dataplane.HostState{IPCommand: true, TUN: true}, boot: "hev", message: "Настройка исполнителя HEV сохранена"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			a, _, adapter := autonomousIntegrationFixture(t)
			s := setAutonomyUSQUEPolicy(t, a, true)
			base := filepath.Dir(a.Dataplane.StateRoot)
			a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: filepath.Join(base, "control")}
			a.EngineConfigs = engineconfig.New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
			a.DataplaneHost = func() dataplane.HostState { return scenario.host }
			a.ProxySidecarBoot = scenario.boot
			if err := a.Dataplane.Register(&autonomyUSQUEApplyModel{}); err != nil {
				t.Fatal(err)
			}
			pkg := &autopilotEnginePackage{name: "sing-box-go"}
			a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, StateDir: t.TempDir()}
			p := a.autonomyPolicy()
			allowInstall := true
			p.InstallMissingComponents = &allowInstall
			service, _ := a.autonomyService(s.ID)
			r, done := a.tryAutonomyInitialUSQUE(ctx, p, s, autonomy.Runtime{}, a.Store.Get(), service, "fixture-network", false)
			if done || r.State != "masque-component-unavailable" || !strings.Contains(r.Message, scenario.message) ||
				len(pkg.commands) != 0 || len(r.Switches) != 0 || len(adapter.calls) != 0 {
				t.Fatalf("local prerequisite consumed a package or Apply attempt: %+v, done=%t, packages=%v, adapter=%v", r, done, pkg.commands, adapter.calls)
			}
		})
	}
}

func TestAutonomyUSQUEPrivateCompanionUsesServicePermission(t *testing.T) {
	for _, scenario := range []string{"usque-only denied", "usque-only allowed", "standalone only", "usque legacy window"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			a, _, _ := autonomousIntegrationFixture(t)
			s := setAutonomyUSQUEPolicy(t, a, true)
			base := filepath.Dir(a.Dataplane.StateRoot)
			control := filepath.Join(base, "control")
			a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: control}
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
				t.Fatal(err)
			}
			if err := a.ConfigureDefaultConsent(filepath.Join(base, "config.json"), filepath.Join(base, "nodes")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.CloseDefaultConsent() })
			a.EngineConfigs = engineconfig.New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
			proxy, err := dataplane.NewProxyTunnelAdapter("usque", a.EngineConfigs, filepath.Join(base, "private-runtime"))
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Dataplane.Register(proxy); err != nil {
				t.Fatal(err)
			}
			if !a.Dataplane.USQUEMissingManagedSidecar(a.EngineConfigs) {
				t.Skip("the environment already provides a Sing-box sidecar")
			}
			a.DataplaneHost = func() dataplane.HostState {
				return dataplane.HostState{IPCommand: true, TUN: true}
			}
			pkg := &autopilotEnginePackage{name: "sing-box-go"}
			a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, StateDir: t.TempDir()}
			now := time.Now().UTC()
			a.autonomy.mu.Lock()
			p := &a.autonomy.doc.Policy
			p.PreferredRoutes = []string{"usque"}
			p.SourceIDs = nil
			allow := scenario != "usque-only denied"
			p.InstallMissingComponents = &allow
			if scenario == "standalone only" {
				p.PreferredRoutes = []string{"sing-box"}
			}
			start := now.Add(8 * time.Hour)
			if scenario == "usque legacy window" {
				p.InstallMissingComponents = nil
				p.Components = autonomy.Window{Mode: "install", Start: start.Format("15:04"), End: start.Add(time.Hour).Format("15:04"), Days: []int{0, 1, 2, 3, 4, 5, 6}}
			}
			err = a.persistAutonomyLocked(ctx)
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			service, _ := a.autonomyService(s.ID)
			network, err := a.freshNetworkProfile(ctx)
			if err != nil {
				t.Fatal(err)
			}
			owned, release, err := a.scopedRuntimeOperation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(release)
			r, _ := a.tryAutonomyInitialUSQUE(owned, a.autonomyPolicy(), s, autonomy.Runtime{}, a.Store.Get(), service, network, false)
			last, err := a.Components.LastInstallAttempt(components.MASQUESidecarComponent)
			if err != nil || len(pkg.commands) != 0 {
				t.Fatalf("private companion touched package manager: last=%v, commands=%v, err=%v", last, pkg.commands, err)
			}
			switch scenario {
			case "usque-only denied":
				if r.State != "component-unavailable" || !strings.Contains(r.Message, "не разрешена") || !last.IsZero() {
					t.Fatalf("explicit deny did not stop acquisition: %+v last=%v", r, last)
				}
			case "usque-only allowed":
				// The production installer was reached, then refused the
				// disposable state root before network or package activity.
				if r.State != "component-unavailable" || !strings.Contains(r.Message, "этой платформы") || last.IsZero() {
					t.Fatalf("USQUE permission did not reach the private installer: %+v last=%v", r, last)
				}
			case "standalone only":
				if r.State != "" || !last.IsZero() {
					t.Fatalf("standalone Sing-box permission reached USQUE: %+v last=%v", r, last)
				}
			case "usque legacy window":
				if r.State != "component-window" || !r.NextCheck.Equal(start.Truncate(time.Minute)) || !last.IsZero() {
					t.Fatalf("legacy window did not pace the sidecar: %+v last=%v", r, last)
				}
			}
			coreAttempt, err := a.Components.LastInstallAttempt("usque")
			if err != nil || !coreAttempt.IsZero() {
				t.Fatalf("missing companion touched the USQUE core journal: %v %v", coreAttempt, err)
			}
		})
	}
}
