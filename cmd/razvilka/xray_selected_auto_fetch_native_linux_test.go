//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Compile-only until Root accepts the immutable CORE replacement composition.
// Root alone runs this opt-in ARM64 test in a private MOUNT namespace sharing
// the actual NETWORK namespace. Require -test.timeout=0: the body has its own
// finite 35m context, while an uncertain original retirement must retain its
// owners instead of being killed by Go's process-wide alarm. Root's detached
// waiter records actual exit only after real retirement and process exit.
// The target
// is 30 real minutes from original scheduled bootstrap LastAttemptAt, never a
// substituted clock, due date or forced worker round. Input names are exactly
// xrayAutoFetchParseInput's RAZVILKA_NATIVE_XRAY_AUTO_* contract.
//
// ROOT/qa-auto-control/status is private JSON. Root atomically writes command
// (0600): FAULT_A <RUN_ID>\n after applied_a; PUBLISHED_C <RUN_ID>\n only after
// exhausted_ab; STOP <RUN_ID>\n after committed_c, or ABORT <RUN_ID>\n anywhere.
// Those commands are intent only. Root faults only the original A remote tuple,
// supplies an independently failing B, and publishes C only on the SAME HTTPS
// feed after exhaustion. The test never imports profiles or performs QueueSync.
// Feed response telemetry must come from the actual completed Job.Result.Fetch;
// missing CORE behavior/telemetry fails explicitly, never substitutes a fixture.
func TestXraySelectedAutoFetchNativeHTTP(t *testing.T) {
	if os.Getenv(xrayAutoFetchPrefix+"ENABLED") != "1" {
		t.Skip("Root-owned AUTO native operation requires explicit opt-in")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=native_environment code=root_arm64_required")
	}
	if _, alarm := t.Deadline(); alarm {
		t.Fatal("stage=inputs code=use_test_timeout_0_to_retain_original_cleanup")
	}
	autoIn, err := xrayAutoFetchParseInput(os.Getenv)
	if err != nil {
		t.Fatal("stage=inputs code=invalid_auto_scope_input")
	}
	in := autoIn.Base
	rootInfo, err := os.Lstat(in.Root)
	entries, readErr := os.ReadDir(in.Root)
	if err != nil || readErr != nil || !xraySelectedSoakPrivate(rootInfo, true) || rootInfo.Mode()&os.ModeSymlink != 0 || len(entries) != 0 {
		t.Fatal("stage=inputs code=empty_private_real_root_required")
	}
	inputs := &xrayAutoHeldInputs{}
	defer inputs.close()
	materials := make([]json.RawMessage, 3)
	for i, path := range autoIn.Profiles {
		raw := inputs.open(t, path, providerprofile.MaxProfileBytes, true)
		materials[i] = xrayAutoMaterial(t, raw)
		clear(raw)
		defer clear(materials[i])
		for j := 0; j < i; j++ {
			if bytes.Equal(materials[i], materials[j]) {
				t.Fatal("stage=inputs code=distinct_actual_material_required")
			}
		}
	}
	urlBytes := inputs.open(t, autoIn.FeedURLFile, 4096, true)
	feedURL, err := xrayAutoFetchURL(urlBytes)
	clear(urlBytes)
	if err != nil {
		t.Fatal("stage=inputs code=original_https_feed_url_required")
	}
	policyBytes := inputs.open(t, in.Scope, 64<<10, true)
	policy, err := xraySelectedScope(policyBytes)
	clear(policyBytes)
	if err != nil {
		t.Fatal("stage=inputs code=original_finite_device_list_scope_required")
	}
	clear(inputs.open(t, in.Catalog, 4<<20, false))
	clear(inputs.open(t, in.Sources, 4<<20, false))
	builtIn, err := catalog.Load(in.Catalog)
	if err != nil || !xraySelectedCatalogAllowsNewQA(builtIn) {
		t.Fatal("stage=catalog code=actual_new_qa_definition_required")
	}
	registry, err := sources.LoadRegistry(in.Sources)
	if err != nil {
		t.Fatal("stage=sources code=actual_registry_required")
	}
	control, err := xrayAutoNewControl(in.Root, autoIn.RunID)
	if err != nil {
		t.Fatal("stage=control code=original_private_control_unavailable")
	}
	defer control.Close()
	trace := xrayAutoFetchChronology{}
	status := xrayAutoNativeStatus{RunID: autoIn.RunID, Phase: "initializing"}
	publish := func(phase string) {
		t.Helper()
		status.Phase, status.UpdatedAt, status.Chronology = phase, time.Now().UTC(), trace
		if control.publish(status) != nil {
			t.Fatal("stage=control code=original_status_publication_refused")
		}
		t.Logf("stage=auto phase=%s", phase)
	}
	publish("initializing")
	runLife, stopRunLife := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRunLife()
	ctx, cancel := context.WithTimeout(runLife, 35*time.Minute)
	defer cancel()
	configPath := filepath.Join(in.Root, "config.json")
	store, err := config.Load(configPath)
	if err != nil {
		t.Fatal("stage=config code=actual_store_unavailable")
	}
	nodes, err := openNodeStore(configPath, "")
	if err != nil {
		t.Fatal("stage=nodes code=actual_private_store_unavailable")
	}
	defer nodes.Close()
	configs := engineconfig.New(filepath.Join(in.Root, "stage"), filepath.Join(in.Root, "backup"))
	fresh := func(ctx context.Context) (string, error) {
		profile, err := systemprobe.FreshWANProfile(ctx)
		return profile.ID, err
	}
	manager, err := newDataplaneManagerWithNodes(filepath.Join(in.Root, "dataplane"), configs, nodes, fresh)
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_adapter_unavailable")
	}
	dns, err := dnscontrol.New(filepath.Join(in.Root, "dns"))
	if err != nil || registerScopedDNS(manager, dns) != nil {
		t.Fatal("stage=main_constructor code=actual_dns_owner_unavailable")
	}
	custom, err := customservices.Load(filepath.Join(in.Root, "custom-services.json"))
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_custom_store_unavailable")
	}
	deviceStore, err := devices.Load(filepath.Join(in.Root, "devices.json"))
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_device_store_unavailable")
	}
	components, err := componentsFromEnv()
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_components_unavailable")
	}
	strategyLab, err := strategylab.New(filepath.Join(in.Root, "strategy-lab.json"))
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_strategy_lab_unavailable")
	}
	strategyLab.Validator = strategylab.CompatibleValidator{}
	strategyLab.Executor = nil
	strategyLab.PackKeys, err = strategylab.LoadPackKeys("")
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_strategy_pack_keys_unavailable")
	}
	files, err := configuredSelfUpdateFiles("/opt", filepath.Join(in.Root, "self-update-files"), filepath.Join(in.Root, "self-update"), filepath.Join(in.Root, "control"))
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_control_unavailable")
	}
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, files.ControlRoot); err != nil {
		t.Fatal("stage=main_constructor code=actual_control_initialization_refused")
	}
	var randomToken [32]byte
	if _, err := rand.Read(randomToken[:]); err != nil {
		t.Fatal("stage=authentication code=entropy_unavailable")
	}
	token := hex.EncodeToString(randomToken[:])
	clear(randomToken[:])
	gate, err := security.NewGate(token)
	if err != nil {
		t.Fatal("stage=authentication code=actual_gate_unavailable")
	}
	a := &app.App{Store: store, Catalog: builtIn, Nodes: nodes, Dataplane: manager, EngineConfigs: configs, DNS: dns, Devices: deviceStore, CustomServices: custom,
		Sources:    sources.NewManager(registry, filepath.Join(in.Root, "source-cache"), filepath.Join(in.Root, "sources-selection.json")),
		Components: components, StrategyLab: strategyLab, Security: gate, SelfUpdate: files.Helper, SelfUpdateFiles: files, FreshProfile: fresh,
		ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion)}
	if a.InitializeComponentRecoveryGate() != nil {
		t.Fatal("stage=main_constructor code=actual_component_gate_refused")
	}
	feedRoot := filepath.Join(in.Root, "subscriptions-private")
	if os.Mkdir(feedRoot, 0700) != nil {
		t.Fatal("stage=feeds code=private_feed_root_unavailable")
	}
	a.NodeFeeds, err = providerfeed.Open(nodes, feedRoot)
	if err != nil {
		t.Fatal("stage=feeds code=persistent_feed_open_refused")
	}
	defer a.NodeFeeds.Close()
	history := updatecheck.NewNodeHistoryAdmission(nodestore.RequiredPrivateHistoryReadVersion, nodestore.ExactHistoryReadVersion)
	if bindNodeHistoryWriteAdmission(a, history.CheckWrite) != nil {
		t.Fatal("stage=main_constructor code=actual_history_binding_refused")
	}
	dispatch, views, err := configuredNodeCheckers(manager.StateRoot)
	if err != nil {
		t.Fatal("stage=main_constructor code=actual_checker_unavailable")
	}
	a.NodeChecker, a.NodeCheckers = views["sing-box"], views
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		if dispatch.Recover(cleanup) != nil {
			t.Error("stage=checker_cleanup code=actual_cleanup_unconfirmed")
		}
		if manager.CloseScopedDNS(cleanup) != nil {
			t.Error("stage=dns_cleanup code=actual_cleanup_unconfirmed")
		}
	}()
	if a.ConfigureDefaultConsent(configPath, filepath.Join(in.Root, "nodes-private")) != nil {
		t.Fatal("stage=main_constructor code=actual_scope_binding_refused")
	}
	defer a.CloseDefaultConsent()
	// The Main managed lifetime survives cancellation of admission, HTTP and
	// soak work. Its original tools remain held until both real owners join.
	managedLife, stopManagedLife := context.WithCancel(context.Background())
	var managedNFQ *app.ManagedNFQWSListRuntime
	var managedXray *app.ManagedXraySelectedTCPListRuntime
	managedJoined := false
	closeManaged := func(cleanup context.Context) error {
		if managedJoined {
			return nil
		}
		if managedXray != nil {
			if err := managedXray.Close(cleanup); err != nil {
				return err
			}
		}
		if managedNFQ != nil {
			if err := managedNFQ.Close(cleanup); err != nil {
				return err
			}
		}
		// Nil handles prove nothing. The SAME App must join its actual recorded
		// startup attempt after every returned runtime has genuinely closed.
		if err := a.CloseManagedListStartup(cleanup); err != nil {
			return err
		}
		managedJoined = true
		stopManagedLife()
		return nil
	}
	// The same production keeper retries actual cleanup with fresh bounded
	// budgets. An unsuccessful Close never lets this test discard the owner.
	defer retainManagedListRetirement(closeManaged)
	nfqStartupStarted := time.Now()
	managedNFQ, err = configureManagedNFQList(managedLife, a)
	nfqStartupElapsed := time.Since(nfqStartupStarted).Milliseconds()
	nfqStartupErr := err
	xrayStartupStarted := time.Now()
	managedXray, err = configureManagedXraySelectedTCPList(managedLife, a)
	xrayStartupElapsed := time.Since(xrayStartupStarted).Milliseconds()
	xrayStartupErr := err
	t.Logf("stage=managed_startup component=nfqws2 elapsed_ms=%d returned_handle=%t startup_stage=%s cause=%s tools_stage=%s inactivity_stage=%s backend_stage=%s wg_source_stage=%s wg_tools_stage=%s", nfqStartupElapsed, managedNFQ != nil, xraySelectedStartupStage(nfqStartupErr), xraySelectedStartupCause(nfqStartupErr), xraySelectedStartupToolStage(nfqStartupErr), xraySelectedStartupInactiveStage(nfqStartupErr), xraySelectedStartupBackendStage(nfqStartupErr), xraySelectedStartupWGSourceStage(nfqStartupErr), xraySelectedStartupWGToolsStage(nfqStartupErr))
	t.Logf("stage=managed_startup component=xray elapsed_ms=%d returned_handle=%t startup_stage=%s cause=%s tools_stage=%s inactivity_stage=%s backend_stage=%s wg_source_stage=%s wg_tools_stage=%s", xrayStartupElapsed, managedXray != nil, xraySelectedStartupStage(xrayStartupErr), xraySelectedStartupCause(xrayStartupErr), xraySelectedStartupToolStage(xrayStartupErr), xraySelectedStartupInactiveStage(xrayStartupErr), xraySelectedStartupBackendStage(xrayStartupErr), xraySelectedStartupWGSourceStage(xrayStartupErr), xraySelectedStartupWGToolsStage(xrayStartupErr))
	if nfqStartupErr != nil || xrayStartupErr != nil || managedNFQ == nil || managedXray == nil {
		t.Fatal("stage=main_constructor code=actual_managed_list_startup_unconfirmed; retain original QA artifacts")
	}

	// Exactly the Main startup order: recovery, initial permission readback,
	// checker/feed managed workers, HTTP serving, then ONE reconciler.
	recoverCtx, recoverCancel := context.WithTimeout(ctx, 2*time.Minute)
	recovery, recoverErr := manager.Recover(recoverCtx)
	checkerErr := dispatch.Recover(recoverCtx)
	recoverCancel()
	if recoverErr != nil || checkerErr != nil || recovery.State == "network-stale" || a.PendingComponentRecovery() || a.PendingSelfUpdateRecovery() {
		t.Fatal("stage=boot_recovery code=original_clean_boot_required")
	}
	if a.PreparePanelAutonomy(ctx) != nil {
		t.Fatal("stage=boot_recovery code=actual_autonomy_readback_refused")
	}
	runtimeLife, stopRuntimeLife := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		stopRuntimeLife()
		t.Fatal("stage=http_server code=local_listener_unavailable")
	}
	server := newPanelHTTPServer(runtimeLife, listener.Addr().String(), a.Handler(http.NotFoundHandler()))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + listener.Addr().String()
	workersStarted, applied, joined := false, false, false
	stopTicket := &xrayAutoStopTicket{}
	// Every retry keeps the SAME HTTP/App/worker/material owners. Neither a
	// canceled parent nor an unknown retirement discards a pending A/C pair.
	defer retainManagedListRetirement(func(cleanup context.Context) error {
		if joined {
			return control.publish(status)
		}
		status.Phase, status.UpdatedAt = "cleanup_unconfirmed", time.Now().UTC()
		_ = control.publish(status)
		needsPublicStop := applied
		if !needsPublicStop {
			// A lost Apply response can still leave a real committed owner.
			// Failed precommit attempts instead join through closeManaged below.
			current, exists, err := manager.Committed()
			cfg := store.Get()
			needsPublicStop = err == nil && exists && current.State == "committed" && current.LAN != nil && current.LAN.Mode == dataplane.LANPolicyXraySelectedTCPMode && current.Revision == cfg.AppliedRevision
		}
		if needsPublicStop {
			if !stopTicket.joined && !stopTicket.stop(cleanup, client, base, token, autoIn.RunID, store) {
				return errors.New("original_public_stop_unconfirmed")
			}
		}
		stopRuntimeLife()
		if err := server.Shutdown(cleanup); err != nil {
			return err
		}
		if workersStarted {
			if err := a.WaitServiceReconciler(cleanup); err != nil {
				return err
			}
			if err := a.WaitNodeRecovery(cleanup); err != nil {
				return err
			}
			if err := a.WaitNodeChecks(cleanup); err != nil {
				return err
			}
			if err := a.WaitNodeFeeds(cleanup); err != nil {
				return err
			}
		}
		if err := dispatch.Recover(cleanup); err != nil {
			return err
		}
		if err := closeManaged(cleanup); err != nil {
			return err
		}
		if err := verifySelfUpdateRuntimeInactive(cleanup, manager); err != nil {
			return err
		}
		if err := manager.CloseScopedDNS(cleanup); err != nil {
			return err
		}
		joined = true
		status.Phase, status.UpdatedAt = "retired", time.Now().UTC()
		if t.Failed() {
			status.Phase = "failed_retired"
		}
		return control.publish(status)
	})
	a.StartNodeChecks(runtimeLife)
	a.StartNodeFeeds(runtimeLife)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	a.StartServiceReconciler(runtimeLife)
	workersStarted = true
	call := func(stage, method, path string, value any, expected int, target any) []byte {
		t.Helper()
		data := xrayAutoCall(t, ctx, client, base, token, stage, method, path, value, expected, target)
		if inputs.current() != nil {
			t.Fatal("stage=inputs code=original_input_changed")
		}
		return data
	}
	wait := func(stage string, ready func() bool) {
		t.Helper()
		for {
			if ctx.Err() != nil || inputs.current() != nil {
				t.Fatalf("stage=%s code=wait_canceled_or_input_changed", stage)
			}
			select {
			case <-serverDone:
				t.Fatal("stage=http_server code=original_server_stopped")
			default:
			}
			command, commandErr := control.read("command", 128)
			if commandErr != nil {
				t.Fatal("stage=control code=original_command_unconfirmed")
			}
			abort := string(command) == "ABORT "+autoIn.RunID+"\n"
			clear(command)
			if abort {
				t.Fatalf("stage=%s code=root_abort_intent", stage)
			}
			if ready() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("stage=%s code=wait_canceled", stage)
			case <-time.After(time.Second):
			}
		}
	}
	intent := func(name string) bool {
		raw, err := control.read("command", 128)
		if err != nil {
			t.Fatal("stage=control code=original_command_unconfirmed")
		}
		defer clear(raw)
		return string(raw) == name+" "+autoIn.RunID+"\n"
	}
	call("manual_bootstrap", "PUT", "/api/v1/service-control", map[string]any{"expected_revision": store.Get().Revision, "mode": "manual", "confirm": "SAVE_SERVICE_CONTROL"}, 200, nil)
	var service catalog.Service
	call("finite_qa_definition", "POST", "/api/v1/custom-services", xraySelectedQAService(in.HTTPS), 201, &service)
	originalCustom := custom.List()
	if service.ID != xraySelectedQAID || len(originalCustom) != 1 || len(service.Domains) != 0 || !slices.Equal(service.CIDRs, xraySelectedQAService(in.HTTPS).CIDRs) {
		t.Fatal("stage=definition code=finite_original_definition_required")
	}
	call("enable_qa_definition", "PUT", "/api/v1/services/"+service.ID, map[string]any{"enabled": true, "route": "direct", "sources": []string{in.Client.String() + "/32"}, "expected_revision": store.Get().Revision}, 200, nil)
	var saved struct {
		OK     bool               `json:"ok"`
		Source providerfeed.State `json:"source"`
	}
	call("save_original_feed", "POST", "/api/v1/node-feeds", map[string]any{"url": feedURL, "format": "profile", "limit": 32, "accept_partial": false, "name": "Root AUTO QA", "enabled": true, "refresh_interval_minutes": 60, "confirm": "SAVE_NODE_FEED"}, 201, &saved)
	feedURL = ""
	if !saved.OK || saved.Source.SourceID == "" || !a.NodeFeeds.Persistent() {
		t.Fatal("stage=feed code=actual_persistent_feed_required")
	}
	sourceID := saved.Source.SourceID
	trace.OriginalSourceID = sourceID
	var bootstrap xrayAutoFeedJob
	var initialState providerfeed.State
	wait("scheduled_bootstrap", func() bool {
		state := xrayAutoSourceState(t, a.NodeFeeds, sourceID)
		if state.JobID == "" {
			return false
		}
		job, err := xrayAutoJob(ctx, client, base, token, state.JobID)
		if err != nil {
			return false
		}
		if job.Status == "queued" || job.Status == "running" {
			return false
		}
		xrayAutoRequireFetch(t, job, sourceID, 2)
		bootstrap, initialState = job, state
		return true
	})
	trace.BootstrapAttempt, trace.BootstrapFinished, trace.NormalRefreshDue = initialState.LastAttemptAt, bootstrap.FinishedAt, initialState.NextRefreshAt
	if trace.BootstrapAttempt.IsZero() || trace.NormalRefreshDue.Before(trace.BootstrapAttempt.Add(time.Hour)) {
		t.Fatal("stage=bootstrap code=original_60m_due_required")
	}
	trace.BootstrapBodySHA256 = xrayAutoCacheDigest(t, feedRoot, sourceID, bootstrap.Result.Fetch.BodySHA256)
	deadlineCancel := cancel
	ctx, cancel = context.WithDeadline(runLife, trace.BootstrapAttempt.Add(xrayAutoFetchBudget))
	deadlineCancel()
	defer cancel()
	var ids []string
	var initialSnapshot nodestore.Snapshot
	wait("bootstrap_materials", func() bool {
		snapshot, matched, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok {
			return false
		}
		if len(snapshot.Nodes) != 2 || matched[0] == "" || matched[1] == "" || matched[2] != "" || matched[0] == matched[1] {
			t.Fatal("stage=bootstrap code=only_original_ab_without_c_required")
		}
		for _, node := range snapshot.Nodes {
			if node.Disabled || len(node.Health.History) != 0 || !xrayAutoOrigin(node, sourceID, time.Now()) {
				t.Fatal("stage=bootstrap code=unmeasured_actual_source_candidates_required")
			}
		}
		initialSnapshot, ids = snapshot, matched
		return true
	})
	trace.BootstrapNodeIDs = [2]string{ids[0], ids[1]}
	status.NodeIDs = [3]string{ids[0], ids[1], ""}
	publish("bootstrap_ab")
	idA, routeA := ids[0], "xray:"+ids[0]
	var checked struct {
		OK                   bool                      `json:"ok"`
		WorkingRoutesChanged bool                      `json:"working_routes_changed"`
		Result               dataplane.NodeCheckResult `json:"result"`
	}
	data := call("actual_check_a", "POST", "/api/v1/nodes/"+idA+"/check", map[string]any{"engine": "xray", "service_id": service.ID, "confirm": "CHECK_NODE"}, 200, &checked)
	if !checked.OK || checked.WorkingRoutesChanged || !checked.Result.Available || checked.Result.DirectLeak || checked.Result.Verdict != evidence.VerdictPass || checked.Result.ServiceID != service.ID || checked.Result.NodeID != idA || checked.Result.RoutePathID != routeA || !checked.Result.Evidence.Valid() || !checked.Result.Evidence.AssuranceLevel().AtLeast(evidence.Service) {
		t.Fatalf("stage=actual_check_a code=%s %s", xraySelectedRefusal(data), xraySelectedCheckDiagnostic(checked.Result))
	}
	wait("actual_history_a", func() bool {
		snapshot, _, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok {
			return false
		}
		if snapshot.Generation != initialSnapshot.Generation+1 || len(snapshot.Nodes) != 2 {
			t.Fatal("stage=actual_history_a code=unexpected_private_store_change")
		}
		for _, node := range snapshot.Nodes {
			if node.ID == idA {
				if len(node.Health.History) != 1 || node.Health.History[0].ProbeID != checked.Result.ProbeID {
					t.Fatal("stage=actual_history_a code=original_check_not_recorded")
				}
				return true
			}
		}
		return false
	})
	call("selected_a", "PUT", "/api/v1/services/"+service.ID, map[string]any{"enabled": true, "route": routeA, "sources": []string{in.Client.String() + "/32"}, "expected_revision": store.Get().Revision}, 200, nil)
	call("actual_device_discovery", "GET", "/api/v1/devices?view=status", nil, 200, nil)
	permission := xraySelectedTCPIntent(store.Get(), service.ID, idA)
	call("tcp_ipv4_intent", "PUT", "/api/v1/service-policies/"+service.ID, map[string]any{"config_revision": store.Get().Revision, "expected_revision": 0, "policy": permission, "confirm": "SAVE_SERVICE_POLICY"}, 200, nil)
	grant := config.DefaultRouteGrant{Resolved: routeA, ProviderClass: "node", ProviderID: idA, SourceIDs: []string{sourceID}, SourceKinds: []string{"subscription"}, Protocols: []string{"vless"}}
	call("original_scope_consent", "POST", "/api/v1/networkpolicy/review", map[string]any{"expected_revision": store.Get().Revision, "expected_policy_revision": 0, "policy": policy, "grants": []config.DefaultRouteGrant{grant}, "confirm": "APPROVE_NETWORK_POLICY"}, 200, nil)
	call("explicit_live_permission", "PUT", "/api/v1/settings/safe-mode", map[string]any{"enabled": false}, 200, nil)
	var reviewed struct {
		Transaction dataplane.Plan `json:"transaction"`
		Review      struct {
			Revision *uint64 `json:"expected_revision"`
			Digest   string  `json:"reviewed_digest"`
		} `json:"review"`
	}
	call("review_a", "GET", "/api/v1/plan?scope=all", nil, 200, &reviewed)
	if reviewed.Review.Revision == nil || *reviewed.Review.Revision != store.Get().Revision || len(reviewed.Review.Digest) != 64 || reviewed.Transaction.Noop || !xrayAutoFinitePlan(reviewed.Transaction, routeA, service, in.Client.String()+"/32") {
		t.Fatal("stage=review_a code=actual_finite_review_required")
	}
	var appliedBody struct {
		OK          bool `json:"ok"`
		LiveApplied bool `json:"live_applied"`
		Pending     bool `json:"scope_pending_changes"`
	}
	call("apply_a", "POST", "/api/v1/apply?scope=all", map[string]any{"expected_revision": *reviewed.Review.Revision, "reviewed_digest": reviewed.Review.Digest}, 200, &appliedBody)
	applied = appliedBody.LiveApplied
	planA, exists, err := manager.Committed()
	if err != nil || !exists || !appliedBody.OK || !appliedBody.LiveApplied || appliedBody.Pending || !planA.Ready || !xrayAutoFinitePlan(planA, routeA, service, in.Client.String()+"/32") || managedXray.Current(ctx) != nil {
		t.Fatal("stage=apply_a code=actual_owned_a_unconfirmed")
	}
	trace.AppliedA = xrayAutoCommittedAt(t, manager, planA)
	var view xrayAutoAutonomyView
	call("read_autonomy", "GET", "/api/v1/autonomy", nil, 200, &view)
	p := view.Policy
	p.SetupComplete, p.Enabled = true, true
	p.InheritNewServices, p.AllLAN = false, false
	p.DefaultSources = []string{in.Client.String() + "/32"}
	p.SourceIDs, p.Protocols, p.PreferredRoutes = []string{sourceID}, []string{"vless"}, []string{}
	p.Application.Mode, p.Components.Mode = "off", "off"
	// Valid ordinary settings, not forged due times or shortened refill cooldown.
	p.CheckSeconds, p.ReserveSeconds, p.FailureConfirmSeconds = 60, 60, 20
	p.ReserveTarget, p.CandidatesPerRound = 3, 2
	call("save_auto_consent", "PUT", "/api/v1/autonomy", map[string]any{"expected_revision": p.Revision, "policy": p, "confirm": "SAVE_AUTONOMY", "release_safe_mode": false}, 200, &view)
	call("enroll_original_service", "POST", "/api/v1/autonomy/services", map[string]any{"service_id": service.ID, "enabled": true, "use_defaults": false, "all_lan": false, "sources": p.DefaultSources, "expected_revision": view.Policy.Revision, "confirm": "MANAGE_SERVICE"}, 200, nil)
	modeBefore := store.Get()
	originalSources, originalFeeds := a.Sources, a.NodeFeeds
	if modeBefore.ServiceControl.Mode != "manual" {
		t.Fatal("stage=auto_control code=original_manual_mode_required")
	}
	call("auto_control", "PUT", "/api/v1/service-control", map[string]any{"expected_revision": modeBefore.Revision, "mode": "auto", "confirm": "SAVE_SERVICE_CONTROL"}, 200, nil)
	// This lower bound describes the completed public request, not a receipt
	// or health grant. Only original persisted checks and completed ordinary
	// reconciler rounds below can confirm that the unchanged A stayed healthy.
	autoAcknowledgedAt := time.Now().UTC()
	originalConfig := store.Get()
	modeAfter := modeBefore
	modeAfter.ServiceControl.Mode, modeAfter.Revision = "auto", modeBefore.Revision+1
	if !reflect.DeepEqual(originalConfig, modeAfter) {
		t.Fatal("stage=auto_control code=actual_mode_only_store_image_required")
	}
	network := checked.Result.NetworkProfile
	healthyAProbes := map[string]bool{}
	var lastHealthyARound time.Time
	// Keep bootstrap_ab until two real post-transition rounds have finished.
	// Root's FAULT_A remains gated by the existing applied_a phase; no manual
	// check, forced round, timer adjustment or replacement Apply is performed.
	wait("actual_retained_a_rechecks", func() bool {
		if a.Operations.Snapshot().Fenced || a.Store != store || a.Nodes != nodes || a.Dataplane != manager || a.Sources != originalSources || a.NodeFeeds != originalFeeds ||
			a.CustomServices != custom || a.DNS != dns || a.SelfUpdateFiles != files || !reflect.DeepEqual(a.Catalog, builtIn) ||
			!reflect.DeepEqual(custom.List(), originalCustom) || !reflect.DeepEqual(store.Get(), originalConfig) {
			t.Fatal("stage=retained_a code=original_owner_or_store_changed")
		}
		current, exists, err := manager.Committed()
		if err != nil || !exists || !reflect.DeepEqual(current, planA) {
			t.Fatal("stage=retained_a code=original_a_plan_changed")
		}
		snapshot, matched, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok {
			return false
		}
		if len(snapshot.Nodes) != 2 || matched[0] != ids[0] || matched[1] != ids[1] || matched[2] != "" {
			t.Fatal("stage=retained_a code=original_ab_materials_changed_or_c_admitted")
		}
		v, ok := xrayAutoReadAutonomy(ctx, client, base, token)
		if !ok {
			return false
		}
		round := v.Runtime[service.ID]
		if round.State == "checking" || !round.CheckedAt.After(autoAcknowledgedAt) || !round.CheckedAt.After(lastHealthyARound) {
			return false
		}
		if v.Blocked || round.State != "healthy" || round.FailureNode != idA || round.Network != network || round.Failures != 0 ||
			!round.FirstFailure.IsZero() || !round.LastFailure.IsZero() || round.CheckedAt.After(time.Now()) {
			t.Fatal("stage=retained_a code=ordinary_healthy_a_round_unconfirmed")
		}
		var exact nodestore.CheckRecord
		for _, node := range snapshot.Nodes {
			if !xrayAutoOrigin(node, sourceID, time.Now()) {
				t.Fatal("stage=retained_a code=original_ab_source_ttl_changed")
			}
			if node.ID != idA {
				continue
			}
			for _, record := range node.Health.History {
				if record.ProbeID != "" && record.ProbeID != checked.Result.ProbeID && record.CheckedAt.After(autoAcknowledgedAt) && !record.CheckedAt.After(round.CheckedAt) &&
					record.ServiceID == service.ID && record.NetworkProfile == network && record.RoutePathID == routeA && record.TestLevel == "service" &&
					record.Verdict == "PASS" && record.State == "available" && !record.DirectLeak && record.ExpiresAt.After(time.Now()) && record.CheckedAt.After(exact.CheckedAt) {
					exact = record
				}
			}
		}
		if exact.ProbeID == "" || healthyAProbes[exact.ProbeID] {
			return false
		}
		if managedXray.Current(ctx) != nil {
			t.Fatal("stage=retained_a code=actual_a_owner_after_mode_or_history_refused")
		}
		if closing, exists, err := manager.Committed(); err != nil || !exists || !reflect.DeepEqual(closing, planA) ||
			!reflect.DeepEqual(store.Get(), originalConfig) || !reflect.DeepEqual(custom.List(), originalCustom) {
			t.Fatal("stage=retained_a code=original_a_closing_changed")
		}
		closingSnapshot, closingMaterials, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok {
			return false
		}
		if len(closingSnapshot.Nodes) != 2 || !slices.Equal(closingMaterials, matched) {
			t.Fatal("stage=retained_a code=original_ab_closing_materials_changed")
		}
		for _, node := range closingSnapshot.Nodes {
			if !xrayAutoOrigin(node, sourceID, time.Now()) {
				t.Fatal("stage=retained_a code=original_ab_closing_source_ttl_changed")
			}
		}
		closingView, ok := xrayAutoReadAutonomy(ctx, client, base, token)
		if !ok || closingView.Blocked || !reflect.DeepEqual(closingView.Runtime[service.ID], round) {
			return false // A new ordinary round may have started during observation.
		}
		healthyAProbes[exact.ProbeID], lastHealthyARound = true, round.CheckedAt
		status.RetainedARechecks = len(healthyAProbes)
		return len(healthyAProbes) >= 2
	})
	publish("applied_a")
	wait("fault_a_intent", func() bool { return intent("FAULT_A") })
	trace.FaultA = time.Now().UTC()
	publish("fault_a_intent")
	var failure1, failure2, failureB nodestore.CheckRecord
	wait("actual_ab_exhaustion", func() bool {
		if a.Operations.Snapshot().Fenced {
			t.Fatal("stage=auto code=original_gate_fenced_no_auto_claim")
		}
		if !reflect.DeepEqual(custom.List(), originalCustom) || !reflect.DeepEqual(store.Get().NetworkPolicy, originalConfig.NetworkPolicy) || !reflect.DeepEqual(store.Get().AppliedNetworkPolicy, originalConfig.AppliedNetworkPolicy) {
			t.Fatal("stage=auto code=original_definition_or_scope_changed")
		}
		snapshot, matched, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok {
			return false
		}
		if len(snapshot.Nodes) != 2 || matched[2] != "" {
			t.Fatal("stage=exhaustion code=c_admitted_before_publication")
		}
		failure1, failure2, failureB = xrayAutoFailureHistory(snapshot.Nodes, [2]string{ids[0], ids[1]}, service.ID, network, trace.FaultA, time.Duration(p.FailureConfirmSeconds)*time.Second, time.Now())
		if !failure1.CheckedAt.IsZero() && trace.FailureA1.IsZero() {
			trace.FailureA1 = failure1.CheckedAt
			publish("failure_a1")
		}
		if !failure2.CheckedAt.IsZero() && trace.FailureA2.IsZero() {
			trace.FailureA2 = failure2.CheckedAt
			publish("failure_a2")
		}
		if failure2.CheckedAt.IsZero() || failureB.CheckedAt.IsZero() || failureB.CheckedAt.Before(failure2.CheckedAt) {
			return false
		}
		v, ok := xrayAutoReadAutonomy(ctx, client, base, token)
		if !ok {
			return false
		}
		r := v.Runtime[service.ID]
		if v.Blocked || r.State == "requires-review" || r.State == "apply-refused" {
			t.Fatal("stage=exhaustion code=actual_auto_guard_refused")
		}
		if r.Search == nil || !r.Search.Exhausted || r.Search.Halted || r.Search.Cursor != len(r.Search.Ordered) || !slices.Contains(r.Search.Ordered, ids[1]) {
			return false
		}
		if r.Failures < 2 || r.FailureNode != ids[0] || r.Network != network || r.LastFailure.Sub(r.FirstFailure) < time.Duration(p.FailureConfirmSeconds)*time.Second {
			return false
		}
		if len(r.Reserves) != 0 || store.Get().AppliedServices[service.ID].Route != routeA {
			t.Fatal("stage=exhaustion code=original_a_changed_without_c_proof")
		}
		trace.FailureB, trace.Exhausted = failureB.CheckedAt, time.Now().UTC()
		return true
	})
	publish("exhausted_ab")
	wait("publish_c_intent", func() bool { return intent("PUBLISHED_C") })
	trace.PublishedC = time.Now().UTC()
	publish("published_c_intent")
	var fetched xrayAutoFeedJob
	var observedDemand bool
	wait("actual_demand_fetch_c", func() bool {
		if a.Operations.Snapshot().Fenced {
			t.Fatal("stage=refill code=original_gate_fenced")
		}
		v, ok := xrayAutoReadAutonomy(ctx, client, base, token)
		if ok && v.Refill.SourceID == sourceID && v.Refill.State == "queued" {
			observedDemand = true
		}
		state := xrayAutoSourceState(t, a.NodeFeeds, sourceID)
		if state.JobID == "" || state.JobID == bootstrap.ID {
			return false
		}
		job, err := xrayAutoJob(ctx, client, base, token, state.JobID)
		if err != nil {
			return false
		}
		if job.CreatedAt.Before(trace.PublishedC) || job.CreatedAt.Before(trace.BootstrapAttempt.Add(15*time.Minute)) {
			t.Fatal("stage=refill code=premature_c_fetch")
		}
		if job.Status == "queued" || job.Status == "running" {
			return false
		}
		xrayAutoRequireFetch(t, job, sourceID, 1)
		if !observedDemand {
			t.Fatal("stage=refill code=actual_demand_producer_unobserved")
		}
		fetched = job
		return true
	})
	trace.JobCreated, trace.RequestStarted, trace.RequestFinished = fetched.CreatedAt, fetched.Result.Fetch.RequestStartedAt, fetched.Result.Fetch.ResponseFinishedAt
	trace.HTTPStatus, trace.FetchedSourceID = fetched.Result.Fetch.HTTPStatus, fetched.SourceID
	trace.FetchedBodySHA256 = xrayAutoCacheDigest(t, feedRoot, sourceID, fetched.Result.Fetch.BodySHA256)
	if trace.FetchedBodySHA256 == trace.BootstrapBodySHA256 {
		t.Fatal("stage=refill code=unchanged_body_c_not_fresh")
	}
	publish("fetched_c")
	var planC dataplane.Plan
	wait("actual_auto_commit_c", func() bool {
		snapshot, matched, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok {
			return false
		}
		if len(snapshot.Nodes) != 3 || matched[2] == "" || matched[2] == ids[0] || matched[2] == ids[1] {
			return false
		}
		idC := matched[2]
		for _, node := range snapshot.Nodes {
			if node.ID == idC {
				if !xrayAutoOrigin(node, sourceID, time.Now()) {
					t.Fatal("stage=admitted_c code=original_source_ttl_missing")
				}
				if trace.AdmittedC.IsZero() {
					trace.AdmittedC = node.AddedAt
					trace.NodeC = idC
					status.NodeIDs[2] = idC
				}
				for _, record := range node.Health.History {
					if record.ServiceID == service.ID && record.NetworkProfile == network && record.RoutePathID == "xray:"+idC && record.TestLevel == "service" && record.Verdict == "PASS" && record.State == "available" && !record.DirectLeak && record.ExpiresAt.After(time.Now()) && !record.CheckedAt.Before(trace.AdmittedC) {
						if trace.CheckedC.IsZero() {
							trace.CheckedC = record.CheckedAt
						}
					}
				}
			}
		}
		if trace.CheckedC.IsZero() {
			return false
		}
		if a.Operations.Snapshot().Fenced {
			t.Fatal("stage=commit_c code=actual_managed_bridge_unconfirmed")
		}
		actual, exists, err := manager.Committed()
		if err != nil || !exists || actual.PlanID == planA.PlanID || actual.State != "committed" || !actual.Ready || !xrayAutoFinitePlan(actual, "xray:"+idC, service, in.Client.String()+"/32") {
			return false
		}
		cfg := store.Get()
		if cfg.AppliedRevision != actual.Revision || cfg.AppliedServices[service.ID].Route != "xray:"+idC || !reflect.DeepEqual(cfg.NetworkPolicy, originalConfig.NetworkPolicy) || !reflect.DeepEqual(cfg.AppliedNetworkPolicy, originalConfig.AppliedNetworkPolicy) || !reflect.DeepEqual(custom.List(), originalCustom) {
			t.Fatal("stage=commit_c code=actual_same_scope_store_commit_missing")
		}
		release, err := a.Operations.Enter(ctx)
		if err != nil {
			return false
		}
		defer release()
		resolved, err := nodes.ResolveRouteForEngine(ctx, "xray", idC, service.ID, network, "", time.Time{}, time.Now())
		if err != nil || resolved.NodeID != idC {
			t.Fatal("stage=commit_c code=latest_exact_c_proof_missing")
		}
		planC = actual
		trace.CommittedC = xrayAutoCommittedAt(t, manager, actual)
		return true
	})
	if managedXray.Current(ctx) != nil {
		t.Fatal("stage=commit_c code=actual_c_owner_observation_refused")
	}
	if xrayAutoFetchChronologyCheck(trace, time.Now(), time.Duration(p.FailureConfirmSeconds)*time.Second) != nil {
		t.Fatal("stage=chronology code=original_demand_chronology_unconfirmed")
	}
	publish("committed_c_pending_rechecks")
	// The original C Apply round must finish and real subsequent AUTO rounds
	// must persist new exact C checks without restarting C or changing its plan.
	// This neither writes history nor invokes a worker round or another fetch.
	wait("actual_retained_c_rechecks", func() bool {
		if a.Operations.Snapshot().Fenced {
			t.Fatal("stage=retained_c code=original_gate_fenced")
		}
		current, exists, err := manager.Committed()
		if err != nil || !exists || !reflect.DeepEqual(current, planC) {
			t.Fatal("stage=retained_c code=original_c_plan_changed")
		}
		snapshot, matched, ok := xrayAutoSnapshot(ctx, a, nodes, materials)
		if !ok || matched[2] != trace.NodeC {
			return false
		}
		probes := map[string]bool{}
		for _, node := range snapshot.Nodes {
			if node.ID != trace.NodeC {
				continue
			}
			if !xrayAutoOrigin(node, sourceID, time.Now()) {
				t.Fatal("stage=retained_c code=original_c_source_changed")
			}
			for _, record := range node.Health.History {
				if record.CheckedAt.After(trace.CommittedC) && record.ServiceID == service.ID && record.NetworkProfile == network && record.RoutePathID == "xray:"+trace.NodeC && record.TestLevel == "service" && record.Verdict == "PASS" && record.State == "available" && !record.DirectLeak && record.ExpiresAt.After(time.Now()) {
					probes[record.ProbeID] = true
				}
			}
		}
		if len(probes) < 2 {
			return false
		}
		v, ok := xrayAutoReadAutonomy(ctx, client, base, token)
		if !ok || v.Runtime[service.ID].State == "checking" {
			return false
		}
		if v.Blocked || v.Runtime[service.ID].State != "healthy" {
			t.Fatal("stage=retained_c code=ordinary_healthy_round_unconfirmed")
		}
		if managedXray.Current(ctx) != nil {
			t.Fatal("stage=retained_c code=actual_c_owner_after_history_refused")
		}
		if closing, exists, err := manager.Committed(); err != nil || !exists || !reflect.DeepEqual(closing, planC) || !reflect.DeepEqual(custom.List(), originalCustom) || !reflect.DeepEqual(store.Get().NetworkPolicy, originalConfig.NetworkPolicy) || !reflect.DeepEqual(store.Get().AppliedNetworkPolicy, originalConfig.AppliedNetworkPolicy) {
			t.Fatal("stage=retained_c code=original_c_closing_changed")
		}
		status.RetainedCRechecks = len(probes)
		return true
	})
	publish("committed_c")
	// Root separately inspects LAN/process/order/conntrack evidence during this
	// bounded hold; chronology/status is not runtime authority or LAN acceptance.
	wait("root_stop_intent", func() bool {
		if intent("STOP") {
			return true
		}
		current, exists, err := manager.Committed()
		if err != nil || !exists || current.PlanID != planC.PlanID {
			t.Fatal("stage=hold_c code=original_c_changed")
		}
		return false
	})
	t.Log("actual automatic HTTPS refill/check/managed commit observed; original public Stop and retirement still required; no hour/LAN acceptance claim")
}

type xrayAutoFeedJob = providerfeed.Job

type xrayAutoAutonomyView struct {
	Policy  autonomy.Policy             `json:"policy"`
	Runtime map[string]autonomy.Runtime `json:"runtime"`
	Refill  providerfeed.RefillDecision `json:"reserve_refill"`
	Blocked bool                        `json:"blocked"`
}

type xrayAutoNativeStatus struct {
	RunID             string                  `json:"run_id"`
	Phase             string                  `json:"phase"`
	UpdatedAt         time.Time               `json:"updated_at"`
	NodeIDs           [3]string               `json:"node_ids"`
	Chronology        xrayAutoFetchChronology `json:"chronology"`
	RetainedARechecks int                     `json:"retained_a_rechecks"`
	RetainedCRechecks int                     `json:"retained_c_rechecks"`
}

func xrayAutoCall(t *testing.T, ctx context.Context, client *http.Client, base, token, stage, method, path string, value any, expected int, target any) []byte {
	t.Helper()
	request, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	status, data, err := xraySelectedCall(request, client, base, token, method, path, value)
	if err != nil || status != expected || target != nil && json.Unmarshal(data, target) != nil {
		t.Fatalf("stage=%s status=%d code=%s %s", stage, status, xraySelectedRefusal(data), xraySelectedReviewDiagnostic(data))
	}
	t.Logf("stage=%s status=%d", stage, status)
	return data
}

func xrayAutoJob(ctx context.Context, client *http.Client, base, token, id string) (xrayAutoFeedJob, error) {
	var response struct {
		Job xrayAutoFeedJob `json:"job"`
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, data, err := xraySelectedCall(c, client, base, token, "GET", "/api/v1/node-feeds/jobs/"+id, nil)
	defer clear(data)
	if err != nil || status != 200 || json.Unmarshal(data, &response) != nil || response.Job.ID != id {
		return xrayAutoFeedJob{}, errors.New("actual_feed_job_unavailable")
	}
	return response.Job, nil
}

func xrayAutoRequireFetch(t *testing.T, job xrayAutoFeedJob, source string, count int) {
	t.Helper()
	if job.Status != "completed" || !job.Scheduled || job.ErrorCode != "" || job.SourceID != source || job.StartedAt.IsZero() || job.CreatedAt.After(job.StartedAt) || job.FinishedAt.Before(job.StartedAt) || job.Result == nil || job.Result.SourceID != source || job.Result.Status != "synced" || job.Result.Imported != count || job.Result.Rejected != 0 || job.Result.Duplicates != 0 || job.Result.Omitted != 0 || job.Result.TotalEntries != count || job.Result.AcceptedEntries != count || job.Result.NotModified {
		t.Fatal("stage=feed code=actual_complete_nonpaged_job_required")
	}
	f := job.Result.Fetch
	if f == nil {
		t.Fatal("stage=feed code=actual_fetch_observation_required")
	}
	digest, err := hex.DecodeString(f.BodySHA256)
	if f.HTTPStatus != 200 || !f.BodyClosed || !f.FreshBody || f.BodyBytes <= 0 || f.BodyBytes > providerfeed.MaxBytes || err != nil || len(digest) != sha256.Size || strings.ToLower(f.BodySHA256) != f.BodySHA256 || f.RequestStartedAt.IsZero() || f.ResponseFinishedAt.Before(f.RequestStartedAt) || f.RequestStartedAt.Before(job.StartedAt) || f.ResponseFinishedAt.After(job.FinishedAt) || job.FinishedAt.After(time.Now()) {
		t.Fatal("stage=feed code=actual_fresh_https_200_required")
	}
}

func xrayAutoSourceState(t *testing.T, feeds *providerfeed.Manager, id string) providerfeed.State {
	t.Helper()
	states := feeds.List()
	if len(states) != 1 || states[0].SourceID != id || !states[0].Enabled || states[0].RefreshIntervalMinutes != 60 || states[0].Limit != 32 || states[0].AcceptPartial || !states[0].RetryAfterAt.IsZero() {
		t.Fatal("stage=feed code=original_single_successful_source_required")
	}
	return states[0]
}

func xrayAutoReadAutonomy(ctx context.Context, client *http.Client, base, token string) (xrayAutoAutonomyView, bool) {
	var view xrayAutoAutonomyView
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, data, err := xraySelectedCall(c, client, base, token, "GET", "/api/v1/autonomy", nil)
	defer clear(data)
	ok := err == nil && status == 200 && json.Unmarshal(data, &view) == nil
	return view, ok
}

func xrayAutoSnapshot(ctx context.Context, a *app.App, nodes *nodestore.Store, materials []json.RawMessage) (nodestore.Snapshot, []string, bool) {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	release, err := a.Operations.Enter(c)
	if err != nil {
		return nodestore.Snapshot{}, nil, false
	}
	defer release()
	snapshot, err := nodes.Snapshot(c, time.Now())
	if err != nil {
		return nodestore.Snapshot{}, nil, false
	}
	ids, err := nodes.MatchImportedMaterials(c, materials)
	return snapshot, ids, err == nil && len(ids) == 3
}

func xrayAutoOrigin(node nodestore.Node, source string, now time.Time) bool {
	return !node.Disabled && len(node.Origins) == 1 && node.Origins[0].SourceID == source && !node.Origins[0].ReceivedAt.After(now) && node.Origins[0].ExpiresAt.After(now)
}

func xrayAutoFinitePlan(plan dataplane.Plan, route string, service catalog.Service, source string) bool {
	if plan.LAN == nil || plan.LAN.Mode != dataplane.LANPolicyXraySelectedTCPMode || len(plan.Routes) != 1 {
		return false
	}
	r := plan.Routes[0]
	return r.Selected == route && r.Resolved == route && r.LogicalServiceID == service.ID && len(r.Domains) == 0 && slices.Equal(r.CIDRs, service.CIDRs) && slices.Equal(r.Sources, []string{source})
}

func xrayAutoCommittedAt(t *testing.T, manager *dataplane.Manager, plan dataplane.Plan) time.Time {
	t.Helper()
	status, err := manager.Status()
	if err != nil || status.Execution == nil || status.Execution.State != "committed" || status.Execution.PlanID != plan.PlanID || status.Execution.Digest != plan.Digest {
		t.Fatal("stage=commit code=actual_execution_ack_required")
	}
	at, err := time.Parse(time.RFC3339Nano, status.Execution.FinishedAt)
	if err != nil || at.After(time.Now()) {
		t.Fatal("stage=commit code=actual_commit_timestamp_required")
	}
	return at
}

func xrayAutoCacheDigest(t *testing.T, root, source, want string) string {
	t.Helper()
	raw := xraySelectedReadFile(t, "original_feed_cache", filepath.Join(root, providerfeed.FileName), providerfeed.MaxStorageBytes, true)
	defer clear(raw)
	var doc struct {
		States []struct {
			State struct {
				SourceID string `json:"source_id"`
			} `json:"state"`
			Snapshot *struct {
				Digest  string `json:"digest"`
				Size    int    `json:"size"`
				Entries int    `json:"entries"`
				Cursor  int    `json:"cursor"`
			} `json:"snapshot"`
			ETag     string `json:"etag"`
			Modified string `json:"modified"`
		} `json:"states"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.States) != 1 {
		t.Fatal("stage=feed_cache code=actual_single_snapshot_required")
	}
	s := doc.States[0]
	if s.State.SourceID != source || s.Snapshot == nil || s.Snapshot.Digest != want || s.Snapshot.Size <= 0 || s.Snapshot.Size > providerfeed.MaxBytes || s.Snapshot.Cursor != s.Snapshot.Entries {
		t.Fatal("stage=feed_cache code=fresh_nonpaged_original_snapshot_required")
	}
	idHash := sha256.Sum256([]byte(source))
	path := filepath.Join(root, "feed-snapshots", "feed-"+hex.EncodeToString(idHash[:])+"-"+want+".private")
	body := xraySelectedReadFile(t, "actual_feed_body", path, providerfeed.MaxBytes, true)
	defer clear(body)
	h := sha256.Sum256(body)
	if len(body) != s.Snapshot.Size || hex.EncodeToString(h[:]) != want {
		t.Fatal("stage=feed_cache code=actual_response_bytes_mismatch")
	}
	return want
}

func xrayAutoMaterial(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	parsed, err := providerprofile.ParseCanonicalProfile(string(raw))
	if err != nil || parsed.Preview.NodeCount != 1 || len(parsed.Preview.Rejected) != 0 {
		t.Fatal("stage=inputs code=one_valid_original_profile_required")
	}
	defer clear(parsed.Config)
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(parsed.Config, &doc) != nil {
		t.Fatal("stage=inputs code=canonical_profile_required")
	}
	for _, out := range doc.Outbounds {
		if out["type"] == "vless" {
			delete(out, "tag")
			material, err := json.Marshal(out)
			if err == nil {
				return material
			}
		}
	}
	t.Fatal("stage=inputs code=original_vless_material_required")
	return nil
}

// Keep identical accepted intent through bounded cleanup retries. Only an
// actual terminal failed/canceled job permits a new key/current revision.
// A lost HTTP acknowledgement never creates another job or cleanup authority.
type xrayAutoStopTicket struct {
	sequence         int
	key              string
	revision, jobID  uint64
	replayed, joined bool
}

func (s *xrayAutoStopTicket) stop(ctx context.Context, client *http.Client, base, token, runID string, store *config.Store) bool {
	if s.joined {
		return true
	}
	if s.key == "" {
		s.sequence++
		s.key, s.revision = fmt.Sprintf("auto-stop-%s-%d", runID, s.sequence), store.Get().Revision
	}
	request := map[string]any{"expected_revision": s.revision, "action": "stop", "confirm": "STOP_OWNED_ROUTES", "idempotency_key": s.key}
	// The second identical POST observes idempotent ACK; later budget retries
	// resume polling this same job, including when Store CAS already stopped it.
	for !s.replayed {
		status, data, err := xraySelectedCall(ctx, client, base, token, "POST", "/api/v1/service-control/runtime", request)
		var accepted struct {
			Job struct {
				ID uint64 `json:"id"`
			} `json:"job"`
		}
		ok := err == nil && status == 202 && json.Unmarshal(data, &accepted) == nil && accepted.Job.ID != 0
		if err == nil && status == http.StatusConflict && s.jobID == 0 && xraySelectedRefusal(data) == "SERVICE_CONTROL_CHANGED" {
			// Actual enqueue refusal confirms there was no accepted Stop. The
			// next keeper attempt may compare the new original Store revision.
			s.key = ""
		}
		clear(data)
		if !ok || s.jobID != 0 && s.jobID != accepted.Job.ID {
			return false
		}
		if s.jobID == 0 {
			s.jobID = accepted.Job.ID
		} else {
			s.replayed = true
		}
	}
	for ctx.Err() == nil {
		status, raw, err := xraySelectedCall(ctx, client, base, token, "GET", "/api/v1/service-control/current", nil)
		var view struct {
			Jobs []struct {
				ID      uint64 `json:"id"`
				State   string `json:"state"`
				Cleanup string `json:"cleanup_outcome"`
			} `json:"durable_jobs"`
		}
		ok := err == nil && status == 200 && json.Unmarshal(raw, &view) == nil
		clear(raw)
		if ok {
			for _, job := range view.Jobs {
				if job.ID == s.jobID {
					if job.State == "completed" {
						s.joined = job.Cleanup == "joined" && store.Get().ServiceControl.Stopped
						return s.joined
					}
					if job.State == "failed" || job.State == "canceled" {
						s.key, s.jobID, s.replayed = "", 0, false
						return false
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
	return false
}

// Held INPUT descriptors are independent of production owners. Their original
// file image/inode bookends detect Root changing credentials or scope mid-run.
type xrayAutoHeldInput struct {
	file   *os.File
	path   string
	info   os.FileInfo
	digest [sha256.Size]byte
	limit  int
}
type xrayAutoHeldInputs struct{ files []xrayAutoHeldInput }

func (h *xrayAutoHeldInputs) open(t *testing.T, path string, limit int, private bool) []byte {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("stage=inputs code=original_input_open_refused")
	}
	f := os.NewFile(uintptr(fd), "auto-private-input")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(limit) || private && !xraySelectedSoakPrivate(info, false) {
		f.Close()
		t.Fatal("stage=inputs code=bounded_original_private_file_required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) != int(info.Size()) {
		f.Close()
		clear(raw)
		t.Fatal("stage=inputs code=original_input_read_refused")
	}
	h.files = append(h.files, xrayAutoHeldInput{f, path, info, sha256.Sum256(raw), limit})
	if h.current() != nil {
		clear(raw)
		t.Fatal("stage=inputs code=original_input_changed")
	}
	return raw
}

func (h *xrayAutoHeldInputs) current() error {
	for _, input := range h.files {
		info, err := input.file.Stat()
		named, pathErr := os.Lstat(input.path)
		if err != nil || pathErr != nil || !os.SameFile(input.info, info) || !os.SameFile(info, named) || named.Mode()&os.ModeSymlink != 0 || input.info.Size() != info.Size() || input.info.Mode() != info.Mode() {
			return errors.New("original_input_changed")
		}
		raw := make([]byte, int(info.Size()))
		n, err := input.file.ReadAt(raw, 0)
		digest := sha256.Sum256(raw)
		clear(raw)
		if err != nil && err != io.EOF || n != int(info.Size()) || digest != input.digest {
			return errors.New("original_input_changed")
		}
	}
	return nil
}
func (h *xrayAutoHeldInputs) close() {
	for _, input := range h.files {
		_ = input.file.Close()
	}
}

type xrayAutoControl struct {
	root, control         *os.File
	rootPath, path, runID string
	rootInfo, info        os.FileInfo
	statusImage           []byte
}

func xrayAutoNewControl(rootPath, runID string) (*xrayAutoControl, error) {
	fail := errors.New("private_auto_control_unavailable")
	rootFD, err := syscall.Open(rootPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	c := &xrayAutoControl{root: os.NewFile(uintptr(rootFD), "qa-auto-root"), rootPath: rootPath, path: filepath.Join(rootPath, "qa-auto-control")}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	c.rootInfo, err = c.root.Stat()
	current, pathErr := os.Lstat(rootPath)
	if err != nil || pathErr != nil || !xraySelectedSoakPrivate(c.rootInfo, true) || !os.SameFile(c.rootInfo, current) || current.Mode()&os.ModeSymlink != 0 {
		return nil, fail
	}
	if syscall.Mkdirat(rootFD, "qa-auto-control", 0700) != nil {
		return nil, fail
	}
	fd, err := syscall.Openat(rootFD, "qa-auto-control", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	c.control = os.NewFile(uintptr(fd), "qa-auto-control")
	c.info, err = c.control.Stat()
	if err != nil || c.current() != nil {
		return nil, fail
	}
	c.runID = runID
	ok = true
	return c, nil
}

func (c *xrayAutoControl) Close() {
	if c.control != nil {
		_ = c.control.Close()
	}
	if c.root != nil {
		_ = c.root.Close()
	}
	clear(c.statusImage)
	// Keep all private status/control/original production artifacts for ROOT.
}

func (c *xrayAutoControl) current() error {
	for _, entry := range []struct {
		file     *os.File
		original os.FileInfo
		path     string
	}{
		{c.root, c.rootInfo, c.rootPath}, {c.control, c.info, c.path},
	} {
		if entry.file == nil || entry.original == nil {
			return errors.New("auto_control_identity_changed")
		}
		held, err := entry.file.Stat()
		current, pathErr := os.Lstat(entry.path)
		if err != nil || pathErr != nil || !xraySelectedSoakPrivate(held, true) || !xraySelectedSoakPrivate(current, true) ||
			current.Mode()&os.ModeSymlink != 0 || !os.SameFile(entry.original, held) || !os.SameFile(held, current) {
			return errors.New("auto_control_identity_changed")
		}
	}
	return nil
}

func (c *xrayAutoControl) read(name string, limit int) ([]byte, error) {
	fail := errors.New("auto_control_file_unconfirmed")
	if c.current() != nil {
		return nil, fail
	}
	fd, err := syscall.Openat(int(c.control.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err == syscall.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, fail
	}
	file := os.NewFile(uintptr(fd), "qa-auto-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !xraySelectedSoakPrivate(info, false) || info.Size() < 1 || info.Size() > int64(limit) {
		return nil, fail
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	after, statErr := file.Stat()
	onPath, pathErr := os.Lstat(filepath.Join(c.path, name))
	if err != nil || len(data) != int(info.Size()) || len(data) > limit || statErr != nil || pathErr != nil || c.current() != nil ||
		!xraySelectedSoakPrivate(after, false) || !xraySelectedSoakPrivate(onPath, false) || !os.SameFile(info, after) || !os.SameFile(info, onPath) ||
		info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || onPath.Mode()&os.ModeSymlink != 0 {
		clear(data)
		return nil, fail
	}
	return data, nil
}

func (c *xrayAutoControl) Command() ([]byte, error) { return c.read("command", 128) }

func (c *xrayAutoControl) publish(s xrayAutoNativeStatus) error {
	fail := errors.New("auto_status_unconfirmed")
	if s.RunID != c.runID || c.current() != nil {
		return fail
	}
	previous, err := c.read("status", 4096)
	defer clear(previous)
	if err != nil || !bytes.Equal(previous, c.statusImage) {
		return fail
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fail
	}
	defer clear(data)
	if len(data) > 4096 {
		return fail
	}
	fd, err := syscall.Openat(int(c.control.Fd()), ".status-next", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fail
	}
	file := os.NewFile(uintptr(fd), "qa-auto-status")
	defer file.Close()
	n, err := file.Write(data)
	if err != nil || n != len(data) || file.Sync() != nil || c.current() != nil {
		return fail
	}
	if syscall.Renameat(int(c.control.Fd()), ".status-next", int(c.control.Fd()), "status") != nil {
		return fail
	}
	clear(c.statusImage)
	c.statusImage = bytes.Clone(data)
	if c.control.Sync() != nil || c.current() != nil {
		return fail
	}
	return nil
}
