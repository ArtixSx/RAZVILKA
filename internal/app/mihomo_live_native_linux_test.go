//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Original component/tool/source/COMMON/TUN owners and real TLS/VLESS peers.
// Only the WAN label/platform classification are modeled; no service/health,
// command ACK, process ownership, routing result or cleanup is injected.
func TestMihomoLiveOriginalApplyStopAndFreshApply(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_LIVE_NATIVE") != "1" {
		t.Skip("disposable original live native workflow")
	}
	lifetime, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	peers := domainOriginalPeers(t, lifetime)
	startMihomoLiveNativeForwarder(t, lifetime)
	provider := netidentity.NewProcProvider()
	tools, err := startuptools.AcquireNativeFixturePolicy(lifetime, provider, os.Getenv("RAZVILKA_DOMAIN_TOOLS_REVIEW"))
	if err != nil {
		t.Fatal("original protected tools", err)
	}
	defer tools.Close()
	descriptor, err := tools.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	backend, err := dataplane.NewBackendInventory(provider, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	nodesRoot := filepath.Join(peers.root, "live-nodes")
	if err = os.Mkdir(nodesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodesRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer nodes.Close()
	// The original encrypted VLESS listener remains in its physical server
	// namespace. The fixture TCP forward gives it a separate physical endpoint
	// from the service IP, so endpoint exclusions cannot carry the service.
	uri := fmt.Sprintf("vless://%s@1.1.1.1:10443?security=tls&sni=front.example&type=tcp", domainOriginalUUID)
	imported, err := nodes.Import(lifetime, nodestore.Source{ID: "manual", Kind: "manual"}, uri, time.Now(), time.Hour, false)
	if err != nil || len(imported.Nodes) != 1 {
		t.Fatal("actual private import", err)
	}
	selected := "mihomo:" + imported.Nodes[0].ID
	service := catalog.Service{ID: "live-listed", Name: "Native IPv4 service", Category: "fixture", Strategy: []string{"mihomo"}, CIDRs: []string{domainOriginalServer + "/32"}, ProbeURL: "https://service.example.com/", Probes: []catalog.Probe{{ID: "primary", URL: "https://service.example.com/", Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, JSON: true, RedirectPolicy: "none"}}, {ID: "required-second", URL: "https://unknown.example.com/", Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, JSON: true, RedirectPolicy: "none"}}}}
	service.Probes[0].Label = "Primary native TLS"
	service.Probes[1].Label = "Second mandatory native TLS"
	if err = catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Services = map[string]config.ServiceState{service.ID: {Enabled: true, Route: selected, Sources: []string{domainOriginalClient + "/32"}}}
	cfgPath := filepath.Join(peers.root, "live-config.json")
	raw, _ := json.Marshal(cfg)
	if err = os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateService(service.ID, cfg.Services[service.ID]); err != nil {
		t.Fatal(err)
	}
	cm := components.New()
	archive, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	hev, err := os.ReadFile(os.Getenv("RAZVILKA_HEV_NATIVE"))
	if err != nil {
		t.Fatal(err)
	}
	cm.Client = &http.Client{Transport: mihomoServiceArchiveTransport(func(r *http.Request) (*http.Response, error) {
		var data []byte
		switch r.URL.String() {
		case "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz":
			data = archive
		case "https://github.com/heiher/hev-socks5-tunnel/releases/download/2.17.1/hev-socks5-tunnel-linux-x86_64":
			data = hev
		default:
			return nil, errors.New("unreviewed native fixture asset")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	manager := dataplane.New("/opt/razvilka/state/dataplane")
	fresh := func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }
	manager.FreshProfile = fresh
	configs := engineconfig.New(filepath.Join(peers.root, "drafts"), filepath.Join(peers.root, "backups"))
	base, err := dataplane.NewProxyTunnelAdapter("sing-box", configs, manager.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	base.Runner = runner
	base.IP, base.IPTables, base.IP6Tables = policyTools.IP, policyTools.IPTables, policyTools.IP6Tables
	if err = manager.Register(base); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Nodes: nodes, Components: cm, Dataplane: manager, EngineConfigs: configs, Catalog: catalog.Catalog{Services: []catalog.Service{service}}, FreshProfile: fresh, ProxySidecarBoot: "hev", ExecutionHistory: updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion), ComponentHistory: updatecheck.NewComponentHistoryAdmission(components.MihomoReleaseReadVersion)}
	controlRoot := filepath.Join(peers.root, "live-control")
	a.SelfUpdateFiles = &SelfUpdateFiles{ControlRoot: controlRoot}
	if _, err = operationgate.InitializeSelfUpdateControl(lifetime, controlRoot); err != nil {
		t.Fatal(err)
	}
	initial, done := context.WithTimeout(lifetime, 110*time.Second)
	defer done()
	held, release, err := a.Operations.ExclusiveContext(initial)
	if err != nil {
		t.Fatal(err)
	}
	control, err := a.Operations.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		release()
		t.Fatal(err)
	}
	defer control.Close()
	guard := func(c context.Context, effect func() error) error {
		if err := control.Current(c); err != nil {
			return err
		}
		return errors.Join(effect(), control.Current(c))
	}
	if err = a.ComponentHistory.CheckWrite(held, components.MihomoReleaseReadVersion); err != nil {
		release()
		t.Fatal(err)
	}
	if result, err := cm.ApplyMihomoGuarded(held, guard, control.WithRename, control.WithStart); err != nil || !result.OK {
		release()
		t.Fatal("native Mihomo install", result, err)
	}
	if result, err := cm.ApplyHEVGuarded(held, guard, control.WithRename); err != nil || !result.OK {
		release()
		t.Fatal("native HEV install", result, err)
	}
	identity, err := provider.Observe(held)
	if err != nil {
		release()
		t.Fatal(err)
	}
	physical := func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
		if p != nil {
			return dataplane.ErrNetworkPolicyIdentity
		}
		return control.Current(c)
	}
	deny := func(context.Context, *dataplane.LANPolicyRuntimePlan, dataplane.LANPolicyEffect) error {
		return dataplane.ErrNetworkPolicyIdentity
	}
	policyGate, err := dataplane.NewNetworkPolicyAdapter(held, dataplane.NetworkPolicyAssemblyOptions{Provider: provider, Binding: &dataplane.LANPolicyReceiptBinding{Runtime: &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: physical}, ApplyGuard: deny, CleanupGuard: deny, RetireCheck: physical}, InventoryCheck: func(c context.Context, got netidentity.Identity, p *dataplane.LANPolicyRuntimePlan) error {
		if got != identity || p != nil {
			return dataplane.ErrNetworkPolicyIdentity
		}
		view, err := backend.Read(c, got)
		if err != nil {
			return err
		}
		return view.RequireComplete()
	}})
	if err != nil {
		release()
		t.Fatal("original policy source", err)
	}
	if err = manager.Register(policyGate); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if err = a.ConfigureMihomoProbe(provider); err != nil {
		t.Fatal(err)
	}
	if err = a.ConfigureMihomoLive(lifetime); err != nil {
		t.Fatal("actual startup live binding", err)
	}
	baseline := mihomoLiveNativeLANRequest(t, lifetime, peers)
	if baseline.Source != domainOriginalClient {
		t.Fatal("physical baseline source", baseline)
	}
	for round := 0; round < 2; round++ {
		apply, cancelApply := context.WithTimeout(lifetime, 110*time.Second)
		actual, release, err := a.Operations.ExclusiveContext(apply)
		if err != nil {
			cancelApply()
			t.Fatal(err)
		}
		current := store.Get()
		source, err := dataplane.ReviewNodeDefaultSource(actual, nodes, selected)
		if err != nil {
			release()
			cancelApply()
			t.Fatal(err)
		}
		if err = source.Current(actual); err != nil {
			release()
			cancelApply()
			t.Fatal(err)
		}
		route := dataplane.Route{ServiceID: service.ID, LogicalServiceID: service.ID, Selected: selected, Resolved: selected, CIDRs: service.CIDRs, Sources: []string{domainOriginalClient + "/32"}, ProbeURL: service.ProbeURL, ProbeService: &service}
		// These factual constructor facts come from the actual successfully bound
		// startup adapter; public Capable remains closed until this test passes.
		plan, err := dataplane.BuildAt(dataplane.Input{Revision: current.Revision + 1, NetworkProfileID: "wan-0123456789ab", Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{{ID: "mihomo", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: dataplane.HostState{IPCommand: true, TUN: true, IPTables: true, IP6Tables: true}}, time.Now().UTC())
		if err != nil || !plan.Ready {
			release()
			cancelApply()
			t.Fatal("genuine closed plan", plan.Blockers, err)
		}
		started := time.Now()
		release()
		frozenService, err := dataplane.FrozenProbeService(plan.Routes[0])
		if err != nil {
			cancelApply()
			t.Fatal(err)
		}
		binding := &mihomoNodeBinding{app: a, store: store, node: source, before: current, catalog: mihomoNodeCatalogClone(a.catalogSnapshot()), plan: plan, service: frozenService, profile: plan.NetworkProfileID}
		binding.self = binding
		// Exercise the real App operationScope/restoreAdmission borrower, rather
		// than a bare Gate context that cannot transfer request ownership.
		server := httptest.NewServer(a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bounded, finish := context.WithTimeout(r.Context(), 110*time.Second)
			defer finish()
			bounded = context.WithValue(bounded, mihomoNodeBindingKey{}, binding)
			bounded = dataplane.WithReviewGuard(bounded, binding.current)
			execution, applyErr := a.applyDataplane(bounded, plan, func() (func() error, error) {
				return binding.commit(bounded)
			})
			detail := ""
			status := http.StatusOK
			if applyErr != nil {
				t.Logf("native_apply_failure deadline_exceeded=%t canceled=%t live_owner_unavailable=%t parent_origin_unavailable=%t", errors.Is(applyErr, context.DeadlineExceeded), errors.Is(applyErr, context.Canceled), errors.Is(applyErr, components.ErrMihomoLiveOwner), errors.Is(applyErr, components.ErrMihomoProbeOrigin))
				detail = applyErr.Error()
				status = http.StatusConflict
			}
			writeJSON(w, status, struct {
				Execution dataplane.Execution `json:"execution"`
				Error     string              `json:"error"`
			}{execution, detail})
		})))
		request, err := http.NewRequestWithContext(apply, http.MethodPost, server.URL+"/api/v1/apply", nil)
		if err != nil {
			server.Close()
			cancelApply()
			t.Fatal(err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			server.Close()
			cancelApply()
			t.Fatal(err)
		}
		var reply struct {
			Execution dataplane.Execution `json:"execution"`
			Error     string              `json:"error"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&reply)
		response.Body.Close()
		server.Close()
		cancelApply()
		if decodeErr != nil || response.StatusCode != http.StatusOK || reply.Execution.State != "committed" {
			t.Fatal("actual native App admission/Apply", reply.Execution, reply.Error, response.StatusCode, decodeErr)
		}
		t.Logf("actual_mihomo_live round=%d apply=%s mandatory_probes=2", round, time.Since(started))
		check, cancelCheck := context.WithTimeout(lifetime, 110*time.Second)
		committed, found, err := manager.Committed()
		if err != nil || !found {
			cancelCheck()
			t.Fatal(err)
		}
		if handled, err := a.observeCommittedMihomo(check, committed); !handled || err != nil {
			cancelCheck()
			t.Fatal("fresh runtime check after Apply release", err)
		}
		native := mihomoLiveNativeLANRequest(t, check, peers)
		if native.Source != domainOriginalServer {
			cancelCheck()
			t.Fatal("actual selected client did not traverse native proxy", native)
		}
		cancelCheck()
		stopped, cancelStop := context.WithTimeout(lifetime, 110*time.Second)
		if round == 1 {
			arm, releaseArm, err := a.Operations.ExclusiveContext(stopped)
			if err != nil {
				cancelStop()
				t.Fatal(err)
			}
			err = dataplane.ArmMihomoLiveClosingNativeFixture(arm, manager, 3)
			releaseArm()
			if err != nil {
				cancelStop()
				t.Fatal(err)
			}
		}
		stopStart := time.Now()
		handled, outcome := a.executeMihomoServiceRuntime(stopped, "stop", store.Get().Revision)
		if round == 1 {
			if !handled || outcome.LiveApplied || a.mihomoProbe.liveStop == nil || !a.mihomoProbe.liveStop.closing {
				cancelStop()
				t.Fatal("original close cut did not retain App cursor", outcome)
			}
			handled, outcome = a.executeMihomoServiceRuntime(stopped, "stop", store.Get().Revision)
		}
		if !handled || !outcome.LiveApplied || a.mihomoProbe.liveStop != nil {
			cancelStop()
			t.Fatal("actual original Stop/retry", outcome)
		}
		t.Logf("actual_mihomo_live round=%d stop=%s closing_retry=%t", round, time.Since(stopStart), round == 1)
		baseline = mihomoLiveNativeLANRequest(t, stopped, peers)
		if baseline.Source != domainOriginalClient {
			cancelStop()
			t.Fatal("Stop did not restore actual physical baseline", baseline)
		}
		cancelStop()
	}
}

func startMihomoLiveNativeForwarder(t *testing.T, ctx context.Context) {
	t.Helper()
	listener, err := net.Listen("tcp4", "1.1.1.1:10443")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				server, err := (&net.Dialer{}).DialContext(ctx, "tcp4", domainOriginalServer+":10443")
				if err != nil {
					return
				}
				defer server.Close()
				client.SetDeadline(time.Now().Add(2 * time.Minute))
				server.SetDeadline(time.Now().Add(2 * time.Minute))
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(server, client); close(copied) }()
				_, _ = io.Copy(client, server)
				client.Close()
				server.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; workers.Wait() })
}

func mihomoLiveNativeLANRequest(t *testing.T, ctx context.Context, p *domainOriginalNativePeers) domainOriginalPeerResult {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "ip", "netns", "exec", p.client, "curl", "--silent", "--show-error", "--fail", "--max-time", "5", "--cacert", filepath.Join(p.root, "ca.pem"), "--resolve", "service.example.com:443:"+domainOriginalServer, "https://service.example.com/")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual isolated client HTTPS: %v %s", err, output)
	}
	var result domainOriginalPeerResult
	if err = json.Unmarshal(output, &result); err != nil || result.Marker != "native-domain-service" {
		t.Fatal("actual peer response", err, string(output))
	}
	return result
}
