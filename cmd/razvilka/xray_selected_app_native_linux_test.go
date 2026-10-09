//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
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
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Root-only native preparation, not an hour/LAN/Telegram acceptance test.
// Build with GOOS=linux GOARCH=arm64 go test -c ./cmd/razvilka; Root runs only
// TestXraySelectedAppNativeHTTP with -test.timeout=20m and these inputs:
// RAZVILKA_NATIVE_XRAY_SELECTED=1
// RAZVILKA_NATIVE_XRAY_SELECTED_ROOT: existing empty private QA directory
// ..._PROFILE: existing private file containing exactly one selected profile
// ..._CATALOG / ..._SOURCES: existing genuine catalog/source registry files
// ..._SCOPE: existing JSON NetworkPolicy intent for one actual selected device
//
//	and one segment, selected_services, NewDevices=base, no rules
//
// ..._HTTPS_IPV4 / ..._CLIENT_IPV4: agreed public Telegram HTTPS pin/LAN PC IPv4
// Component paths remain ordinary configuredComponentsFromEnv bindings.
// Original controller/downgrade admission remains real /opt/bin/razvilka.
//
// Known at Root88f998fb: the selected TCP Xray publisher and Main->App Apply
// integration are not installed yet. Custom CIDRs do not manufacture an applied
// ServiceCIDRReview/cache receipt either. A public API refusal is a FAIL stage,
// never an alternate launcher, READY fixture, forged journal or PASS gate.
func TestXraySelectedAppNativeHTTP(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_XRAY_SELECTED") != "1" {
		t.Skip("Root-owned genuine ARM64 App operation requires explicit opt-in")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=native_environment code=root_arm64_required")
	}
	in, err := xraySelectedParseInput(os.Getenv)
	if err != nil {
		t.Fatal("stage=inputs code=invalid_paths_or_addresses")
	}
	rootInfo, err := os.Lstat(in.Root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&077 != 0 || rootInfo.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("stage=inputs code=private_real_root_required")
	}
	entries, err := os.ReadDir(in.Root)
	if err != nil || len(entries) != 0 {
		t.Fatal("stage=inputs code=empty_qa_root_required")
	}
	profile := xraySelectedReadFile(t, "selected_profile", in.Profile, providerprofile.MaxProfileBytes, true)
	defer clear(profile)
	parsed, err := providerprofile.ParseCanonicalProfile(string(profile))
	if err != nil || parsed.Preview.NodeCount != 1 || len(parsed.Preview.Rejected) != 0 {
		t.Fatal("stage=selected_profile code=one_valid_selected_profile_required")
	}
	policyBytes := xraySelectedReadFile(t, "scope_intent", in.Scope, 64<<10, true)
	policy, err := xraySelectedScope(policyBytes)
	clear(policyBytes)
	if err != nil {
		t.Fatal("stage=scope_intent code=one_device_list_only_required")
	}
	builtIn, err := catalog.Load(in.Catalog)
	if err != nil {
		t.Fatal("stage=catalog code=actual_catalog_unavailable")
	}
	telegramDomains := false
	for _, service := range builtIn.Services {
		telegramDomains = telegramDomains || service.ID == "telegram" && len(service.Domains) > 0
		if service.ID == xraySelectedQAID {
			t.Fatal("stage=catalog code=qa_definition_must_be_new")
		}
	}
	if !telegramDomains {
		t.Fatal("stage=catalog code=built_in_telegram_domains_required")
	}
	registry, err := sources.LoadRegistry(in.Sources)
	if err != nil {
		t.Fatal("stage=sources code=actual_registry_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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
		Components: components, Security: gate, SelfUpdate: files.Helper, SelfUpdateFiles: files, FreshProfile: fresh,
		ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion)}
	if a.InitializeComponentRecoveryGate() != nil {
		t.Fatal("stage=main_constructor code=actual_component_gate_refused")
	}
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
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("stage=http_server code=local_listener_unavailable")
	}
	serverLife, stopServerLife := context.WithCancel(context.Background())
	defer stopServerLife()
	server := newPanelHTTPServer(serverLife, listener.Addr().String(), a.Handler(http.NotFoundHandler()))
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + listener.Addr().String()
	call := func(stage, method, route string, value any, expected int, target any) []byte {
		t.Helper()
		status, data, err := xraySelectedCall(ctx, client, base, token, method, route, value)
		if err != nil || status != expected || target != nil && json.Unmarshal(data, target) != nil {
			t.Fatalf("stage=%s status=%d code=%s", stage, status, xraySelectedRefusal(data))
		}
		t.Logf("stage=%s status=%d", stage, status)
		return data
	}
	call("manual_mode", "PUT", "/api/v1/service-control", map[string]any{"expected_revision": store.Get().Revision, "mode": "manual", "confirm": "SAVE_SERVICE_CONTROL"}, 200, nil)
	var service catalog.Service
	call("custom_service", "POST", "/api/v1/custom-services", xraySelectedQAService(in.HTTPS), 201, &service)
	if len(service.Domains) != 0 || service.ID != xraySelectedQAID || !reflect.DeepEqual(service.CIDRs, xraySelectedQAService(in.HTTPS).CIDRs) || !reflect.DeepEqual(a.Catalog, builtIn) {
		t.Fatal("stage=custom_service code=definition_changed_or_built_in_modified")
	}
	call("enable_qa_definition", "PUT", "/api/v1/services/"+service.ID,
		map[string]any{"enabled": true, "route": "direct", "sources": []string{in.Client.String() + "/32"}, "expected_revision": store.Get().Revision}, 200, nil)
	call("private_import", "POST", "/api/v1/nodes/import", map[string]any{"profile": string(profile), "engine": "xray", "confirm": "STORE_REMOTE_NODES"}, 200, nil)
	clear(profile)
	before, err := nodes.Snapshot(ctx, time.Now())
	if err != nil || len(before.Nodes) != 1 || before.Nodes[0].Protocol != "vless" || len(before.Nodes[0].Health.History) != 0 {
		t.Fatal("stage=private_import code=fresh_single_node_without_history_required")
	}
	id, route := before.Nodes[0].ID, "xray:"+before.Nodes[0].ID
	var checked struct {
		OK                   bool                      `json:"ok"`
		WorkingRoutesChanged bool                      `json:"working_routes_changed"`
		Result               dataplane.NodeCheckResult `json:"result"`
	}
	data := call("exact_public_check", "POST", "/api/v1/nodes/"+id+"/check", map[string]any{"engine": "xray", "service_id": service.ID, "confirm": "CHECK_NODE"}, 200, &checked)
	result := checked.Result
	if !checked.OK || checked.WorkingRoutesChanged || !result.Available || result.DirectLeak || result.ServiceID != service.ID || result.NodeID != id || result.RoutePathID != route || result.TestLevel != "service" || result.Verdict != evidence.VerdictPass || !result.Evidence.Valid() ||
		!result.Evidence.AssuranceLevel().AtLeast(evidence.Service) || result.Evidence.Engine != "xray" || result.Evidence.Service != service.ID || result.Evidence.NetworkProfile != result.NetworkProfile || result.Evidence.ExpectedRoutePathID != route || result.Evidence.ObservedRoutePathID != route {
		t.Fatalf("stage=exact_public_check code=%s", xraySelectedRefusal(data))
	}
	after, err := nodes.Snapshot(ctx, time.Now())
	if err != nil || after.Generation != before.Generation+1 || len(after.Nodes) != 1 || len(after.Nodes[0].Health.History) != 1 {
		t.Fatal("stage=persisted_check code=actual_history_missing")
	}
	record := after.Nodes[0].Health.History[0]
	if record.ProbeID != result.ProbeID || record.ServiceID != service.ID || record.RoutePathID != route || record.NetworkProfile != result.NetworkProfile || record.Verdict != "PASS" || record.State != "available" || record.DirectLeak || !record.CheckedAt.Equal(result.FinishedAt) || !record.ExpiresAt.After(time.Now()) || !reflect.DeepEqual(custom.List(), []catalog.Service{service}) {
		t.Fatal("stage=persisted_check code=exact_definition_history_mismatch")
	}
	call("selected_node_route", "PUT", "/api/v1/services/"+service.ID,
		map[string]any{"enabled": true, "route": route, "sources": []string{in.Client.String() + "/32"}, "expected_revision": store.Get().Revision}, 200, nil)
	call("actual_device_discovery", "GET", "/api/v1/devices?view=status", nil, 200, nil)
	permission := config.DefaultServicePolicy(service.ID, store.Get().Services[service.ID])
	permission.Enabled, permission.Mode, permission.PinnedNodeID = true, "manual", id
	permission.AllowedEngines, permission.AllowedNodeIDs = []string{"xray"}, []string{id}
	permission.Scenario = config.ServiceScenario{Kind: "web", RequireUDP: false, RequireIPv6: false}
	call("tcp_ipv4_intent", "PUT", "/api/v1/service-policies/"+service.ID,
		map[string]any{"config_revision": store.Get().Revision, "expected_revision": 0, "policy": permission, "confirm": "SAVE_SERVICE_POLICY"}, 200, nil)
	grant := config.DefaultRouteGrant{Resolved: route, ProviderClass: "node", ProviderID: id, SourceIDs: []string{"manual"}, SourceKinds: []string{"manual"}, Protocols: []string{"vless"}}
	call("original_scope_consent", "POST", "/api/v1/networkpolicy/review",
		map[string]any{"expected_revision": store.Get().Revision, "expected_policy_revision": 0, "policy": policy, "grants": []config.DefaultRouteGrant{grant}, "confirm": "APPROVE_NETWORK_POLICY"}, 200, nil)
	call("live_write_permission", "PUT", "/api/v1/settings/safe-mode", map[string]any{"enabled": false}, 200, nil)
	var plan struct {
		Transaction dataplane.Plan `json:"transaction"`
		Review      struct {
			Revision *uint64 `json:"expected_revision"`
			Digest   string  `json:"reviewed_digest"`
		} `json:"review"`
	}
	call("original_plan_review", "GET", "/api/v1/plan?scope=services", nil, 200, &plan)
	if plan.Review.Revision == nil || *plan.Review.Revision != store.Get().Revision || len(plan.Review.Digest) != 64 || plan.Transaction.Noop || len(plan.Transaction.Routes) != 1 || plan.Transaction.Routes[0].Selected != route {
		t.Fatal("stage=original_plan_review code=original_nonempty_review_required")
	}
	if _, err := hex.DecodeString(plan.Review.Digest); err != nil {
		t.Fatal("stage=original_plan_review code=original_digest_invalid")
	}
	plannedRoute := plan.Transaction.Routes[0]
	if len(plannedRoute.Domains) != 0 || !slices.Equal(plannedRoute.CIDRs, service.CIDRs) || !slices.Equal(plannedRoute.Sources, []string{in.Client.String() + "/32"}) || plan.Transaction.Ready && plan.Transaction.LAN == nil {
		t.Fatal("stage=original_plan_review code=selected_list_scope_missing_or_widened")
	}
	stopConfirmed := false
	defer func() {
		if stopConfirmed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		status, data, err := xraySelectedCall(cleanup, client, base, token, "POST", "/api/v1/service-control/runtime",
			map[string]any{"expected_revision": store.Get().Revision, "action": "stop", "confirm": "STOP_OWNED_ROUTES"})
		if err != nil || status != 200 {
			t.Errorf("stage=apply_cleanup status=%d code=%s; retain original QA journal for Root", status, xraySelectedRefusal(data))
		}
	}()
	// Explicit field tags are required; accepted/reviewed/partial is never active.
	var applyBody struct {
		OK          bool `json:"ok"`
		LiveApplied bool `json:"live_applied"`
		Pending     bool `json:"scope_pending_changes"`
	}
	call("original_apply", "POST", "/api/v1/apply?scope=services",
		map[string]any{"expected_revision": *plan.Review.Revision, "reviewed_digest": plan.Review.Digest}, 200, &applyBody)
	committed, exists, err := manager.Committed()
	if err != nil || !applyBody.OK || !applyBody.LiveApplied || applyBody.Pending || !exists || committed.State != "committed" || len(committed.Routes) != 1 || committed.Routes[0].Selected != route || manager.ObserveCommittedRuntime(ctx, committed) != nil {
		t.Fatal("stage=active_runtime code=actual_owned_runtime_unconfirmed")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		var stopped struct {
			OK bool `json:"ok"`
		}
		call("ordinary_stop", "POST", "/api/v1/service-control/runtime",
			map[string]any{"expected_revision": store.Get().Revision, "action": "stop", "confirm": "STOP_OWNED_ROUTES"}, 200, &stopped)
		if !stopped.OK || !store.Get().ServiceControl.Stopped {
			t.Fatal("stage=ordinary_stop code=actual_stop_unconfirmed")
		}
	}
	stoppedPlan, exists, err := manager.Committed()
	if err != nil || !exists || stoppedPlan.State != "committed" || len(stoppedPlan.Routes) != 0 || verifySelfUpdateRuntimeInactive(ctx, manager) != nil {
		t.Fatal("stage=retirement code=actual_runtime_absence_unconfirmed")
	}
	stopConfirmed = true
	t.Log("actual original App import/check/persisted history/review/Apply/runtime/Stop/repeatedStop completed; HTTPS-only exact check, no hour, physical LAN, proxy path or authenticated Telegram acceptance")
}

func xraySelectedReadFile(t *testing.T, stage, path string, limit int, private bool) []byte {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("stage=%s code=existing_regular_file_required", stage)
	}
	file := os.NewFile(uintptr(fd), "selected-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(limit) || private && (info.Mode().Perm()&077 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0) {
		t.Fatalf("stage=%s code=bounded_private_input_required", stage)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	current, pathErr := os.Lstat(path)
	if err != nil || len(data) > limit || pathErr != nil || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 || strings.TrimSpace(string(data)) == "" {
		clear(data)
		t.Fatalf("stage=%s code=input_changed_or_incomplete", stage)
	}
	return data
}
