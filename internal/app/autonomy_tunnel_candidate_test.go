package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/warp"
)

type initialWARPApplyModel struct{ nodeApplyAdapter }

func (*initialWARPApplyModel) ID() string { return "warp-wg" }

func TestAutonomyInitialWARPEntersScopedCanaryAndAllowsCleanFallback(t *testing.T) {
	const fixtureEnv = "RAZVILKA_TEST_AUTONOMY_INITIAL_WARP_TLS"
	if os.Getenv(fixtureEnv) != "loopback" {
		child := exec.Command(os.Args[0], "-test.run=^TestAutonomyInitialWARPEntersScopedCanaryAndAllowsCleanFallback$")
		child.Env = append(os.Environ(), fixtureEnv+"=loopback")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("loopback registration plus modeled transaction: %v\n%s", err, output)
		}
		return
	}

	for _, scenario := range []struct {
		name               string
		registrationReject bool
		endpointReject     bool
		endpointOnly       bool
		canaryError        error
		healthError        error
		wantFallback       bool
		wantFence          bool
		setup              string
		wantInstalls       int
		skipRegistration   bool
		autoConsent        string
		revokeConsent      string
		existingProfile    string
	}{
		{name: "apply after scoped canary and live health"},
		{name: "wizard consent installs immediately and applies without health authority", setup: "daytime", autoConsent: "true", wantInstalls: 1},
		{name: "explicit Auto refusal overrides legacy health consent", autoConsent: "false", skipRegistration: true, wantFallback: true},
		{name: "stopped saved WARP is checked and applied without registration consent", autoConsent: "false", existingProfile: "live", skipRegistration: true},
		{name: "an unrelated WARP draft is preserved without registration consent", autoConsent: "false", existingProfile: "staged", skipRegistration: true, wantFallback: true},
		{name: "revoked Auto consent prevents first installation", setup: "daytime", autoConsent: "true", revokeConsent: "install", skipRegistration: true},
		{name: "revoked Auto consent rejects the registration response", autoConsent: "true", revokeConsent: "registration"},
		{name: "install missing client then register and apply", setup: "missing", wantInstalls: 1},
		{name: "install missing client outside its update window", setup: "daytime", wantInstalls: 1},
		{name: "on-demand installation retries without an update window", setup: "daytime-retry", wantInstalls: 1, skipRegistration: true},
		{name: "Cloudflare terms not accepted", setup: "no-consent", skipRegistration: true, wantFallback: true},
		{name: "initial WARP preparation disabled", setup: "initial-disabled", skipRegistration: true, wantFallback: true},
		{name: "WARP omitted from Auto methods", setup: "method-disabled", skipRegistration: true, wantFallback: true},
		{name: "component installation disabled", setup: "install-disabled", skipRegistration: true, wantFallback: true},
		{name: "closed night window continues VLESS", setup: "window-fallback", skipRegistration: true, wantFallback: true},
		{name: "closed night window schedules exact retry", setup: "window-only", skipRegistration: true},
		{name: "revoked WARP consent never issues package or enrollment", setup: "revoked", skipRegistration: true},
		{name: "failed package continues VLESS", setup: "install-failed", wantInstalls: 1, skipRegistration: true, wantFallback: true},
		{name: "package unverified preserves other WireGuard files", setup: "install-unverified", wantInstalls: 1, skipRegistration: true, wantFallback: true},
		{name: "registration unavailable", registrationReject: true, wantFallback: true},
		{name: "unreachable registration endpoint continues VLESS", endpointReject: true, skipRegistration: true, wantFallback: true},
		{name: "first registration retries after an unreachable endpoint", endpointReject: true, skipRegistration: true, endpointOnly: true},
		{name: "candidate rejected with clean canary", canaryError: errors.New("HTTPS request failed"), wantFallback: true},
		{name: "live health refused without independent rollback confirmation", healthError: errors.New("live policy verification failed")},
		{name: "owned canary cleanup unknown", canaryError: dataplane.ErrPolicyAdditionUnknown, wantFence: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var requests, probes atomic.Int32
			var endpointAvailable atomic.Bool
			endpointAvailable.Store(!scenario.endpointReject)
			registrationRevoke := make(chan func() error, 1)
			revocationResult := make(chan error, 1)
			issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "api.cloudflareclient.com" || r.URL.Path != "/v0a4471/reg" || r.Method != http.MethodHead && r.Method != http.MethodPost {
					t.Error("unexpected registration destination")
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Method == http.MethodHead {
					probes.Add(1)
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				requests.Add(1)
				if scenario.registrationReject {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				var body struct{ Key, TOS string }
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.TOS == "" || len(body.Key) != 44 {
					t.Error("invalid registration body")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if scenario.revokeConsent == "registration" {
					err := (<-registrationRevoke)()
					revocationResult <- err
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
				}
				peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 32))
				fmt.Fprintf(w, `{"id":"fixture-id","token":"fixture-token","key":%q,"key_type":"curve25519","tunnel_type":"wireguard","config":{"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::2"}},"peers":[{"public_key":%q,"endpoint":{"v4":"162.159.192.1:0","ports":[2408,500]}}]}}`, body.Key, peer)
			}))
			t.Cleanup(issuer.Close)
			original := http.DefaultTransport
			transport := original.(*http.Transport).Clone()
			trust := issuer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			trust.ServerName = "127.0.0.1"
			transport.DialTLSContext = func(c context.Context, network, address string) (net.Conn, error) {
				if address != "api.cloudflareclient.com:443" {
					return nil, errors.New("non-fixture TLS request")
				}
				if !endpointAvailable.Load() {
					return nil, context.DeadlineExceeded
				}
				return (&tls.Dialer{Config: trust}).DialContext(c, network, issuer.Listener.Addr().String())
			}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })

			a, nodes, reserve := autonomousIntegrationFixture(t)
			ctx := context.Background()
			now := time.Now().UTC()
			pkg := &autopilotEnginePackage{name: "wireguard-tools", installed: scenario.setup == ""}
			pkg.unverified = scenario.setup == "install-unverified"
			if scenario.setup == "install-failed" || scenario.setup == "daytime-retry" {
				pkg.installErr = errors.New("fixture Entware unreachable")
			}
			if scenario.setup != "" {
				a.Components = &components.Manager{Opkg: "fixture-opkg", Runner: pkg, StateDir: t.TempDir(), RepoDir: t.TempDir(), BinDir: t.TempDir()}
				a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
					return true, false, "fixture"
				}
			}
			const id = "my-independent-site"
			for i := range a.Catalog.Services {
				if a.Catalog.Services[i].ID == id {
					a.Catalog.Services[i].ProbeURL = "https://93.184.216.34/"
				}
			}
			service, _ := a.autonomyService(id)
			a.autonomy.mu.Lock()
			s := a.autonomy.doc.Services[id]
			s.Definition = autonomyDefinition(service)
			a.autonomy.doc.Services[id] = s
			a.autonomy.doc.Policy.PreferredRoutes = []string{"warp-wg", "sing-box"}
			if scenario.setup == "method-disabled" {
				a.autonomy.doc.Policy.PreferredRoutes = []string{"sing-box"}
			}
			window := &a.autonomy.doc.Policy.Components
			if scenario.setup != "" {
				window.Mode = "install"
			}
			window.Start, window.End = now.Add(-time.Hour).Format("15:04"), now.Add(time.Hour).Format("15:04")
			if scenario.setup == "install-disabled" {
				allow := false
				a.autonomy.doc.Policy.InstallMissingComponents = &allow
			}
			if scenario.setup == "daytime" || scenario.setup == "daytime-retry" {
				allow := true
				a.autonomy.doc.Policy.InstallMissingComponents = &allow
				window.Mode = "off"
			}
			if scenario.setup == "window-only" || scenario.setup == "window-fallback" || scenario.setup == "daytime" || scenario.setup == "daytime-retry" {
				window.Start, window.End = now.Add(time.Hour).Format("15:04"), now.Add(2*time.Hour).Format("15:04")
			}
			if scenario.setup == "window-only" || scenario.setup == "daytime-retry" || scenario.endpointOnly {
				a.autonomy.doc.Policy.SourceIDs = nil
				a.autonomy.doc.Policy.PreferredRoutes = []string{"warp-wg"}
			}
			err := a.persistAutonomyLocked(ctx)
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
			configs.LiveRoot = filepath.Join(root, "live")
			a.EngineConfigs = configs
			a.Warp = warp.New(filepath.Join(root, "warp"), filepath.Join(root, "warp-backup"), configs)
			const existingWARP = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 162.159.192.1:2408\n"
			if scenario.existingProfile == "live" {
				profile, err := configs.ReadExpert("warp-wg", "main")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(profile.Path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(profile.Path, []byte(existingWARP), 0600); err != nil {
					t.Fatal(err)
				}
			} else if scenario.existingProfile == "staged" {
				if _, err := configs.Stage("warp-wg", "main", existingWARP); err != nil {
					t.Fatal(err)
				}
			}
			policy := a.Warp.Health().Policy
			if scenario.autoConsent != "true" {
				policy.Enabled, policy.AcceptTOS, policy.AutoPrepareInitial = true, true, true
			}
			if scenario.setup == "no-consent" || scenario.setup == "initial-disabled" {
				policy.AcceptTOS = scenario.setup != "no-consent"
				policy.AutoPrepareInitial = false
			}
			if _, err := a.Warp.UpdateHealthPolicy(policy); err != nil {
				t.Fatal(err)
			}
			saveAutoConsent := func(allowed bool) error {
				p := a.autonomyPolicy()
				p.AllowInitialWARPRegistration = &allowed
				response := httptest.NewRecorder()
				a.autonomyAPI(response, autonomyRequest(http.MethodPut, "/api/v1/autonomy", map[string]any{
					"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY",
				}))
				if response.Code != http.StatusOK {
					return fmt.Errorf("saving Auto consent: %d %s", response.Code, response.Body.String())
				}
				return nil
			}
			if scenario.autoConsent != "" {
				if err := saveAutoConsent(scenario.autoConsent == "true"); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.revokeConsent == "registration" {
				registrationRevoke <- func() error { return saveAutoConsent(false) }
			}
			if scenario.revokeConsent == "install" {
				pkg.observe = func(command string) {
					if command == "list-installed" {
						pkg.observe = nil
						if err := saveAutoConsent(false); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if scenario.setup == "revoked" {
				pkg.observe = func(command string) {
					if command == "list-installed" {
						pkg.observe = nil
						policy.AutoPrepareInitial = false
						if _, err := a.Warp.UpdateHealthPolicy(policy); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			options := a.nodeReviews.options
			a.nodeReviews.options = func() []routecatalog.Option {
				configured := a.validStagedWARPProfile() || a.reusableAutonomyWARPProfile()
				return append(options(), routecatalog.Option{ID: "warp-wg", Installed: pkg.installed, Configured: configured, Selectable: configured})
			}
			model := &initialWARPApplyModel{}
			model.after = func(stage string) error {
				if stage == "canary" {
					return scenario.canaryError
				}
				if stage == "health" {
					return scenario.healthError
				}
				if stage != "commit" {
					return nil
				}
				candidate, err := configs.ReadExpert("warp-wg", "main")
				if scenario.existingProfile == "live" {
					if err != nil || candidate.Source != "live" || candidate.Content != existingWARP || len(model.planned.EngineDrafts) != 0 {
						return errors.New("the committed WARP profile became an unrelated draft")
					}
					return nil
				}
				if err != nil || candidate.Source != "staged" || !slices.Equal(model.planned.EngineDrafts, []string{"warp-wg/main"}) {
					return errors.New("scoped transaction lost its WARP draft")
				}
				if err := os.MkdirAll(filepath.Dir(candidate.Path), 0700); err != nil {
					return err
				}
				if err := os.WriteFile(candidate.Path, []byte(candidate.Content), 0600); err != nil {
					return err
				}
				return configs.Discard("warp-wg", "main")
			}
			if err := a.Dataplane.Register(model); err != nil {
				t.Fatal(err)
			}
			a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				if !scenario.wantFallback {
					t.Fatal("unexpected VLESS fallback")
				}
				return d10Result(req, "sing-box", true), nil
			})
			a.autonomyRound(ctx, now)
			if scenario.revokeConsent == "registration" {
				select {
				case err := <-revocationResult:
					if err != nil {
						t.Fatal(err)
					}
				default:
					t.Fatal("the registration response was not subject to revocation")
				}
			}
			if a.Warp.Health().Policy != policy {
				t.Fatal("Auto registration changed the independent health policy")
			}
			if scenario.existingProfile != "" {
				profile, err := configs.ReadExpert("warp-wg", "main")
				if err != nil || profile.Source != scenario.existingProfile || profile.Content != existingWARP {
					t.Fatal("an existing profile was changed or consumed", profile.Source, err)
				}
			}
			final := a.Store.Get().AppliedServices[id]
			runtime := autonomyTestState(a)
			state := runtime.State
			wantRequests := int32(1)
			if scenario.skipRegistration {
				wantRequests = 0
			}
			if requests.Load() != wantRequests || probes.Load() != wantRequests || a.Operations.Snapshot().Fenced != scenario.wantFence {
				t.Fatalf("registration posts=%d state=%s WARP=%v VLESS=%v", requests.Load(), state, model.calls, reserve.calls)
			}
			if scenario.endpointReject && len(a.Warp.Health().State.Attempts) != 0 {
				t.Fatal("unreachable endpoint consumed a registration attempt")
			}
			installs := 0
			for _, command := range pkg.commands {
				if command == "install wireguard-tools" {
					installs++
				}
				if command == "remove wireguard-tools" || command == "upgrade wireguard-tools" {
					t.Fatalf("first start changed package ownership: %v", pkg.commands)
				}
			}
			if installs != scenario.wantInstalls || scenario.wantInstalls == 0 && scenario.setup != "revoked" && scenario.revokeConsent != "install" && len(pkg.commands) != 0 {
				t.Fatalf("unexpected package IO: %v", pkg.commands)
			}
			switch {
			case scenario.endpointOnly:
				if final.Enabled || state != "warp-registration-unreachable" || !runtime.NextCheck.After(now) || len(model.calls) != 0 {
					t.Fatalf("unreachable endpoint lost its automatic retry: %+v", runtime)
				}
				endpointAvailable.Store(true)
				a.autonomyRound(ctx, runtime.NextCheck.Add(time.Second))
				if requests.Load() != 1 || probes.Load() != 1 || selectedRoute(a.Store.Get().AppliedServices[id]) != "warp-wg" || !slices.Contains(model.calls, "health") {
					t.Fatalf("recovered endpoint did not register and apply: %+v calls=%v", autonomyTestState(a), model.calls)
				}
			case scenario.setup == "daytime-retry":
				last, err := a.Components.LastInstallAttempt("warp-wg")
				due := last.Add(autonomyInstallRetry)
				if err != nil || last.IsZero() || final.Enabled || state != "component-retry" ||
					runtime.NextCheck.Before(due) || runtime.NextCheck.After(due.Add(2*time.Second)) || len(model.calls) != 0 || len(reserve.calls) != 0 {
					t.Fatalf("failed install did not keep its bounded daytime retry: due=%v runtime=%+v err=%v", due, runtime, err)
				}
			case scenario.setup == "window-only":
				p := a.autonomyPolicy()
				next := autonomy.NextWindow(p.Components, p.Timezone, now)
				if final.Enabled || state != "component-window" || !runtime.NextCheck.Equal(next) || len(model.calls) != 0 || len(reserve.calls) != 0 {
					t.Fatalf("did not wait for exact installation window: next=%v runtime=%+v", next, runtime)
				}
			case scenario.setup == "revoked" || scenario.revokeConsent != "":
				wantState := "paused"
				if scenario.revokeConsent != "" {
					wantState = "pending"
					if !runtime.NextCheck.IsZero() {
						t.Fatalf("new policy did not requeue the service: %+v", runtime)
					}
				}
				if final.Enabled || state != wantState || len(model.calls) != 0 || len(reserve.calls) != 0 {
					t.Fatalf("permission revocation did not stop the round: %+v", runtime)
				}
				profile, err := configs.ReadExpert("warp-wg", "main")
				if err != nil || profile.Source != "missing" {
					t.Fatal("revoked preparation published a profile", profile.Source, err)
				}
			case scenario.wantFence:
				if final.Enabled || state != "requires-review" || slices.Contains(model.calls, "activate") {
					t.Fatal("uncertain cleanup did not stop fallback", state, model.calls)
				}
			case scenario.healthError != nil:
				if final.Enabled || state != "apply-refused" || !slices.Contains(model.calls, "rollback") || slices.Contains(model.calls, "commit") {
					t.Fatal("a failed Health escaped rollback", state, model.calls)
				}
			case scenario.wantFallback:
				if state != "applied" || selectedRoute(final) != "sing-box:"+nodes[0] || slices.Contains(model.calls, "activate") || !slices.Contains(reserve.calls, "health") {
					t.Fatal("clean refusal did not reach VLESS", state, final, model.calls, reserve.calls)
				}
			default:
				if state != "applied" || selectedRoute(final) != "warp-wg" || !slices.Equal(final.Sources, s.Sources) ||
					!slices.Equal(model.calls, []string{"snapshot", "stage", "validate", "canary", "activate", "health", "commit"}) {
					t.Fatal("first WARP did not pass scoped Apply and Health", state, final, model.calls)
				}
			}
		})
	}
}

func TestAutonomyInitialWARPRequiresHTTPSInsideItsOwnCIDR(t *testing.T) {
	for _, tc := range []struct {
		name, url, prefix string
		domains           []string
		probes            []catalog.Probe
		want              bool
	}{
		{name: "target matches", url: "https://93.184.216.34/", prefix: "93.184.216.0/24", want: true},
		{name: "outside route", url: "https://93.184.216.34/", prefix: "93.184.217.0/24"},
		{name: "unbound hostname", url: "https://example.org/", prefix: "93.184.216.0/24"},
		{name: "domains still require domain authority", url: "https://93.184.216.34/", prefix: "93.184.216.0/24", domains: []string{"example.org"}},
		{name: "specialized service predicate", url: "https://93.184.216.34/", prefix: "93.184.216.0/24",
			probes: []catalog.Probe{{Required: true, URL: "https://93.184.216.34/", Expect: catalog.ProbeExpectation{JSON: true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if autonomyWARPService(catalog.Service{ProbeURL: tc.url, CIDRs: []string{tc.prefix}, Domains: tc.domains, Probes: tc.probes}) != tc.want {
				t.Fatal("unexpected WARP service capability")
			}
		})
	}
}
