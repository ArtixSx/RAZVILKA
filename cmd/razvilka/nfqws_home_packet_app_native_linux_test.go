//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Diagnostic observations only: the detached runner owns the actual exit file.
// A pending record never authorizes cleanup or confirms process termination.
type nfqHomeNativeProgress struct {
	Schema         int    `json:"schema"`
	OwnerPID       int    `json:"owner_pid"`
	UpdatedAt      string `json:"updated_at"`
	LastStage      string `json:"last_stage"`
	CleanupStage   string `json:"cleanup_stage"`
	Cleanup        string `json:"cleanup"`
	Attempts       uint64 `json:"attempts"`
	TestBodyFailed bool   `json:"test_body_failed"`
}

func writeNFQHomeNativeProgress(root *os.Root, progress nfqHomeNativeProgress) error {
	data, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".native-retirement-progress-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return root.Rename(name, "native-retirement-progress.json")
}

// Root-only optional stock ARM64 harness, never run by ordinary tests.
// Existing genuine managed receipt is mandatory; an opkg installation, copied
// descriptor/receipt, saved COMPATIBLE flag or fake source cannot replace it.
//
// RAZVILKA_NFQ_HOME_APP=stock-nc1812
// RAZVILKA_NFQ_HOME_APP_ROOT=<new empty real 0700 private directory>
// RAZVILKA_COMPONENT_STATE=<actual installer-owned Components state directory>
// RAZVILKA_NFQ_HOME_APP_HOME=<explicit actual Home segment>
// RAZVILKA_NFQ_HOME_APP_CIDR=<one canonical public IPv4 destination prefix>
// RAZVILKA_NFQ_HOME_APP_PROBE_URL=<explicit HTTPS endpoint for that service>
// RAZVILKA_NFQ_HOME_APP_ARGUMENTS=<explicit managed TCP4 candidate arguments>
// Optional RAZVILKA_NFQ_HOME_APP_EXCLUDED_ID=<canonical literal mac-* ID>.
//
// Default: genuine no-intercept compatibility helper dry-run/Lua and private
// source/config writes, then original source/component/material /plan only.
// productionSelfUpdateFiles selects the real configured control roots; its
// original journal may be initialized, so this is NOT wholly private metadata.
// Root must supply/prepare that actual control deployment as in the existing
// installed-compatibility harness. No receipt or control proof is fabricated.
// No NFQUEUE, forwarding, route, client probe or DNS mutation is requested.
// ONLY RAZVILKA_NFQ_HOME_APP_APPLY=APPLY_HOME_PACKET enables actual /apply,
// retained check and Stop. There is no single-client source selector: Sources
// must remain empty and the explicitly approved scope is the selected Home.
func TestManagedNFQInstalledHomePacketAppHTTP(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQ_HOME_APP") != "stock-nc1812" {
		t.Skip("coordinator-owned stock ARM64 genuine managed receipt required")
	}
	if _, alarm := t.Deadline(); alarm {
		t.Fatal("stage=preflight code=use_test_timeout_0_to_retain_original_cleanup")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=preflight code=actual_root_arm64_required")
	}
	mode := os.Getenv("RAZVILKA_NFQ_HOME_APP_APPLY")
	if mode != "" && mode != "APPLY_HOME_PACKET" {
		t.Fatal("stage=preflight code=unknown_apply_optin")
	}
	apply := mode == "APPLY_HOME_PACKET"
	root, stateRoot := os.Getenv("RAZVILKA_NFQ_HOME_APP_ROOT"), os.Getenv("RAZVILKA_COMPONENT_STATE")
	for _, p := range []string{root, stateRoot} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			t.Fatal("stage=preflight code=explicit_canonical_roots_required")
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 {
		t.Fatal("stage=preflight code=private_real_root_required")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("stage=preflight code=new_empty_root_required")
	}
	if root == stateRoot || strings.HasPrefix(stateRoot, root+string(filepath.Separator)) || strings.HasPrefix(root, stateRoot+string(filepath.Separator)) {
		t.Fatal("stage=preflight code=independent_source_and_component_roots_required")
	}
	home := os.Getenv("RAZVILKA_NFQ_HOME_APP_HOME")
	destination, err := netip.ParsePrefix(os.Getenv("RAZVILKA_NFQ_HOME_APP_CIDR"))
	if home == "" || err != nil || !destination.Addr().Is4() || destination != destination.Masked() || destination.String() != os.Getenv("RAZVILKA_NFQ_HOME_APP_CIDR") || !destination.Addr().IsGlobalUnicast() || destination.Addr().IsPrivate() || destination.Bits() < 8 {
		t.Fatal("stage=preflight code=explicit_home_and_public_ipv4_prefix_required")
	}
	probe := os.Getenv("RAZVILKA_NFQ_HOME_APP_PROBE_URL")
	parsed, err := url.Parse(probe)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		t.Fatal("stage=preflight code=explicit_https_probe_required")
	}
	arguments := os.Getenv("RAZVILKA_NFQ_HOME_APP_ARGUMENTS")
	if strings.TrimSpace(arguments) == "" {
		t.Fatal("stage=preflight code=explicit_candidate_arguments_required")
	}
	policy := config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{home}}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	if id := os.Getenv("RAZVILKA_NFQ_HOME_APP_EXCLUDED_ID"); id != "" {
		policy.Clients.ExcludedDeviceIDs = []string{id}
	}
	if config.ValidateListNetworkPolicy(&policy) != nil {
		t.Fatal("stage=preflight code=invalid_explicit_policy")
	}
	// Setup, a production Apply (bounded separately to eight minutes), and
	// retained Check/Stop must fit in one fixed body window. The old five-minute
	// whole-test caller canceled real Apply573 while its original rollback was
	// still running. No production or material deadline is extended here, and
	// the original retirement keeper remains independent of this body expiry.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	owner := components.New()
	owner.StateDir = stateRoot
	installed, err := owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("stage=component_source code=genuine_existing_managed_receipt_required; use the reviewed first-install path, never manufacture a receipt")
	}
	descriptor := installed.Descriptor()
	if err = installed.Close(); err != nil {
		t.Fatal("stage=component_source code=original_bootstrap_lease_close_refused")
	}
	configPath := filepath.Join(root, "config.json")
	store, err := config.Load(configPath)
	if err != nil {
		t.Fatal("stage=app code=private_store_unavailable")
	}
	strategy, err := strategylab.New(filepath.Join(root, "strategy-lab.json"))
	if err != nil {
		t.Fatal("stage=app code=private_source_unavailable")
	}
	strategy.Validator, strategy.Executor = strategylab.CompatibleValidator{}, nil
	configs := engineconfig.New(filepath.Join(root, "staged"), filepath.Join(root, "backups"))
	manager, err := newDataplaneManager(filepath.Join(root, "dataplane"), configs)
	if err != nil {
		t.Fatal("stage=app code=ordinary_dataplane_constructor_refused")
	}
	dns, err := dnscontrol.New(filepath.Join(root, "dns.json"))
	if err != nil {
		t.Fatal("stage=app code=private_dns_owner_unavailable")
	}
	// Main registers the same concrete DNS participant separately from the
	// ordinary adapter factory. Startup needs its inactivity owner even though
	// this CIDR-only fixture never requests a DNS plan or listener.
	if err := registerScopedDNS(manager, dns); err != nil {
		t.Fatal("stage=app code=ordinary_scoped_dns_registration_refused")
	}
	files, err := productionSelfUpdateFiles()
	if err != nil {
		t.Fatal("stage=app code=original_control_configuration_refused")
	}
	if _, err = operationgate.InitializeSelfUpdateControl(ctx, files.ControlRoot); err != nil {
		t.Fatal("stage=app code=original_control_initialization_refused")
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		t.Fatal("stage=authentication code=entropy_unavailable")
	}
	token := hex.EncodeToString(entropy[:])
	clear(entropy[:])
	sec, err := security.NewGate(token)
	if err != nil {
		t.Fatal("stage=authentication code=actual_gate_unavailable")
	}
	const serviceID = "native-home-packet"
	catalogue := catalog.Catalog{Services: []catalog.Service{{ID: serviceID, Name: "Native Home packet QA", Category: "test", CIDRs: []string{destination.String()}, ProbeURL: probe, Strategy: []string{"nfqws2"}}}}
	if catalog.Validate(catalogue) != nil {
		t.Fatal("stage=app code=explicit_service_definition_refused")
	}
	a := &app.App{Store: store, Catalog: catalogue, StrategyLab: strategy, Components: owner, Dataplane: manager, EngineConfigs: configs, DNS: dns, Security: sec, SelfUpdate: files.Helper, SelfUpdateFiles: files, ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion)}
	if err = a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal("stage=app code=component_recovery_gate_refused")
	}
	if err = a.ConfigureDefaultConsent(configPath, ""); err != nil {
		t.Fatal("stage=app code=original_scope_owner_refused")
	}
	defer a.CloseDefaultConsent()
	// Keep the original managed lifetime independent of HTTP/context expiry.
	// Even a constructor failure must join its actual recorded startup attempt;
	// a nil handle is never substituted for proof of known inactive ownership.
	progressRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal("stage=native_progress code=private_progress_root_refused")
	}
	defer progressRoot.Close()
	progress := nfqHomeNativeProgress{Schema: 1, OwnerPID: os.Getpid(), LastStage: "managed_startup", Cleanup: "pending", CleanupStage: "not_started"}
	publishProgress := func() {
		progress.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		progress.TestBodyFailed = t.Failed()
		if writeNFQHomeNativeProgress(progressRoot, progress) != nil {
			// Diagnostics must never abort the SAME owner's cleanup attempt.
			t.Error("stage=native_progress code=private_progress_write_refused")
		}
	}
	publishProgress()
	managedLife, stopManagedLife := context.WithCancel(context.Background())
	var list *app.ManagedNFQWSListRuntime
	attempted, joined := false, false
	compatibilityHTTPMS := int64(-1)
	closeManaged := func(cleanup context.Context) error {
		if joined {
			publishProgress()
			return nil
		}
		progress.Attempts++
		progress.CleanupStage = "compatibility_join"
		publishProgress()
		if err := a.WaitManagedStrategyCompatibility(cleanup); err != nil {
			return err
		}
		if list != nil {
			progress.CleanupStage = "runtime_join"
			publishProgress()
			if err := list.Close(cleanup); err != nil {
				return err
			}
		}
		if attempted {
			progress.CleanupStage = "startup_join"
			publishProgress()
			if err := a.CloseManagedListStartup(cleanup); err != nil {
				return err
			}
		}
		progress.CleanupStage = "control_close"
		publishProgress()
		if err := a.CloseManagedNFQControl(); err != nil {
			return err
		}
		joined = true
		stopManagedLife()
		progress.Cleanup, progress.CleanupStage = "joined", "joined"
		publishProgress()
		// All original closes above succeeded. Diagnostic output cannot delay
		// native retirement, consume its deadline or replace its result.
		timing, timingErr := json.Marshal(struct {
			Kind   string                                         `json:"kind"`
			HTTPMS int64                                          `json:"http_ms"`
			Timing strategylab.ManagedCompatibilityTimingSnapshot `json:"timing"`
		}{"managed-compatibility-timing", compatibilityHTTPMS, strategy.ManagedCompatibilityTimings()})
		if timingErr != nil {
			t.Error("stage=compatibility_timing code=diagnostic_encoding_refused")
		} else {
			t.Logf("%s", timing)
		}
		return nil
	}
	defer func() {
		publishProgress() // Capture Fatalf/Goexit before entering retained retries.
		retainManagedListRetirement(closeManaged)
		publishProgress()
	}()
	if _, err = configureManagedNFQCompatibility(ctx, a); err != nil {
		t.Fatal("stage=source code=original_installed_compatibility_provider_refused")
	}
	attempted = true
	list, err = configureManagedNFQList(managedLife, a)
	if err != nil || list == nil {
		t.Fatalf("stage=runtime code=ordinary_stock_constructor_refused boundary=%s inactivity_binding=%s nfq_inactivity=%s backend_unknown=%t cancelled=%t deadline=%t", app.ManagedListStartupFailureStage(err), dataplane.RuntimeInactivityBindingStage(err), dataplane.NFQWSRuntimeInactiveStage(err), errors.Is(err, dataplane.ErrBackendInventoryUnknown), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(stage, method, path string, body any, want int, out any) {
		t.Helper()
		if stage == "native_compatibility" {
			started := time.Now()
			defer func() { compatibilityHTTPMS = time.Since(started).Milliseconds() }()
		}
		progress.LastStage = stage // Internal constant labels, never HTTP data.
		publishProgress()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatalf("stage=%s code=request_encoding_refused", stage)
			}
		}
		request, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("stage=%s code=request_unavailable", stage)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Origin", server.URL)
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("stage=%s code=actual_http_unconfirmed", stage)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil || response.StatusCode != want {
			var code struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(data, &code)
			t.Fatalf("stage=%s status=%d code=%s", stage, response.StatusCode, code.Code)
		}
		if out != nil && json.Unmarshal(data, out) != nil {
			t.Fatalf("stage=%s code=response_schema_refused", stage)
		}
		t.Logf("stage=%s status=%d", stage, response.StatusCode)
	}
	beforeCompatibility := store.Get()
	var candidate strategylab.Candidate
	call("candidate_draft", "POST", "/api/v1/strategy-lab/candidates", map[string]string{"pool_id": "tcp-tls", "name": "Home packet native QA", "arguments": arguments}, http.StatusCreated, &candidate)
	if candidate.ID == "" {
		t.Fatal("stage=candidate_draft code=actual_candidate_missing")
	}
	var checked strategylab.Candidate
	call("native_compatibility", "POST", "/api/v1/strategy-lab/candidates/"+candidate.ID+"/validate", map[string]any{}, http.StatusOK, &checked)
	if checked.ID != candidate.ID || !checked.Validation.OK || !checked.Validation.Native || !checked.Validation.LuaChecked || checked.Validation.QuiescenceUnknown || checked.Validation.Code != "COMPATIBLE" || strategy.Snapshot().QuiescenceUnknown || !reflect.DeepEqual(beforeCompatibility, store.Get()) {
		t.Fatal("stage=native_compatibility code=actual_compatible_source_unconfirmed")
	}
	var selected strategylab.Selection
	call("frozen_manual_source", "POST", "/api/v1/strategy-lab/selections", map[string]string{"mode": "manual", "service_id": serviceID, "protocol": "tcp", "ip_family": "ipv4", "candidate_id": candidate.ID}, http.StatusOK, &selected)
	if selected.Mode != strategylab.ModeManual || !selected.Frozen || selected.CandidateID != candidate.ID || selected.Healthy || selected.LastHealthyAt != "" || selected.Confidence != 0 {
		t.Fatal("stage=frozen_manual_source code=source_or_neutral_health_unconfirmed")
	}
	if !reflect.DeepEqual(beforeCompatibility, store.Get()) || strategy.Executor != nil || strategy.Snapshot().Safety["temporary_scoped_firewall_probe"] != false {
		t.Fatal("stage=frozen_manual_source code=unrequested_configuration_or_probe")
	}
	// All writes below are ordinary authenticated metadata/scope writers. They
	// select the whole explicitly chosen Home, with no per-service IP whitelist.
	call("private_working_mode", "PUT", "/api/v1/settings/safe-mode", map[string]bool{"enabled": false}, http.StatusOK, nil)
	call("save_literal_service", "PUT", "/api/v1/services/"+serviceID, config.ServiceState{Enabled: true, Route: "nfqws2"}, http.StatusOK, nil)
	var approved struct {
		Live bool `json:"live_applied"`
	}
	call("approve_explicit_home", "POST", "/api/v1/networkpolicy/review", map[string]any{"expected_revision": store.Get().Revision, "expected_policy_revision": 0, "policy": policy, "grants": []config.DefaultRouteGrant{}, "confirm": "APPROVE_NETWORK_POLICY"}, http.StatusOK, &approved)
	if approved.Live || !config.CurrentDefaultRouteScopeConsent(store.Get()) || len(store.Get().Services[serviceID].Sources) != 0 {
		t.Fatal("stage=approve_explicit_home code=scope_or_source_contract_changed")
	}
	sourceBefore, err := os.ReadFile(strategy.Path)
	if err != nil {
		t.Fatal("stage=plan code=actual_saved_source_unavailable")
	}
	configBefore := store.Get()
	var planned struct {
		Review      json.RawMessage `json:"review"`
		Health      string          `json:"service_health"`
		Transaction dataplane.Plan  `json:"transaction"`
	}
	call("original_prepare_review", "GET", "/api/v1/plan", nil, http.StatusOK, &planned)
	if len(planned.Review) == 0 || planned.Health != "unverified" || !planned.Transaction.Ready || planned.Transaction.Noop || planned.Transaction.LAN == nil || planned.Transaction.LAN.Mode != dataplane.LANPolicyNFQWSDirectMode || len(planned.Transaction.LAN.Ingress) != 1 || planned.Transaction.LAN.Ingress[0].Membership != "all" || len(planned.Transaction.Routes) != 1 {
		t.Fatal("stage=plan code=actual_original_home_review_unconfirmed")
	}
	route := planned.Transaction.Routes[0]
	ingress := planned.Transaction.LAN.Ingress[0]
	if len(route.Sources) != 1 {
		t.Fatal("stage=plan code=exact_single_home_source_missing")
	}
	source, err := netip.ParsePrefix(route.Sources[0])
	if err != nil || !source.Addr().Is4() || route.LogicalServiceID != serviceID || route.Resolved != "nfqws2" || len(route.Sources) != 1 || !slices.Equal(route.Ingress, []string{ingress.Interface}) || !slices.Equal(route.CIDRs, []string{destination.String()}) || !slices.Equal(ingress.Sources, route.Sources) || len(ingress.IncludedMACs) != 0 {
		t.Fatal("stage=plan code=exact_literal_home_shape_changed")
	}
	sourceAfter, err := os.ReadFile(strategy.Path)
	if err != nil || !bytes.Equal(sourceBefore, sourceAfter) || !reflect.DeepEqual(configBefore, store.Get()) {
		t.Fatal("stage=plan code=review_mutated_saved_inputs")
	}
	if _, found, err := manager.Committed(); err != nil || found {
		t.Fatal("stage=plan code=unexpected_committed_execution")
	}
	current, err := owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("stage=plan code=original_review_leaked_component_lease")
	}
	actual := current.Descriptor()
	closeErr := current.Close()
	if closeErr != nil || !reflect.DeepEqual(actual, descriptor) || a.Operations.Snapshot().Active != 0 {
		t.Fatal("stage=plan code=original_review_not_settled")
	}
	t.Log("actual managed receipt -> native dry-run/Lua -> frozen source -> original Home packet/component/material plan; service_health=unverified; network_effects_requested=false")
	if apply {
		var applied struct {
			OK     bool   `json:"ok"`
			Live   bool   `json:"live_applied"`
			Health string `json:"service_health"`
		}
		call("explicit_native_apply", "POST", "/api/v1/apply", planned.Review, http.StatusOK, &applied)
		if !applied.OK || !applied.Live || applied.Health != "unverified" {
			t.Fatal("stage=apply code=actual_execution_unconfirmed")
		}
		for _, action := range []string{"check", "stop", "stop"} {
			var observed struct {
				OK     bool   `json:"ok"`
				State  string `json:"runtime_state"`
				Health string `json:"service_health"`
			}
			call("retained_"+action, "POST", "/api/v1/strategy-lab/runtime", map[string]string{"action": action}, http.StatusOK, &observed)
			want := "native-active"
			if action == "stop" {
				want = "stopped"
			}
			if !observed.OK || observed.State != want || observed.Health != "unverified" {
				t.Fatal("stage=retained_runtime code=actual_state_unconfirmed")
			}
		}
		t.Log("explicit actual NFQ Apply -> retained Check -> original Stop twice passed; no client-traffic or domain-list health claim")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if err = closeManaged(cleanup); err != nil {
		t.Fatal("stage=cleanup code=original_owners_unconfirmed; retaining original lifetime for retry")
	}
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("stage=cleanup code=original_operation_not_released")
	}
}
