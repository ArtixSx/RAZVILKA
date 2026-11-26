package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

const xraySelectedQAID = "custom-qa-xray-selected-tcp"
const xraySelectedTelegramDC2 = "149.154.167.51/32"
const xraySelectedMaxResponse = 1 << 20

func xraySelectedTCPIntent(cfg config.Config, serviceID, nodeID string) config.ServicePolicy {
	// This settings endpoint retains the actual applied device boundary. The
	// selected /32 draft is authorized separately by network policy and Apply.
	permission := config.DefaultServicePolicy(serviceID, cfg.AppliedServices[serviceID])
	permission.Enabled, permission.Mode, permission.PinnedNodeID = true, "manual", nodeID
	permission.AllowedEngines, permission.AllowedNodeIDs = []string{"xray"}, []string{nodeID}
	permission.Scenario = config.ServiceScenario{Kind: "web", RequireUDP: false, RequireIPv6: false}
	return permission
}

func xraySelectedCatalogAllowsNewQA(c catalog.Catalog) bool {
	return !slices.ContainsFunc(c.Services, func(service catalog.Service) bool { return service.ID == xraySelectedQAID })
}

// Only fixed producer enums and bounded scalars leave this projection.
// Result identities, addresses, evidence and free-form messages stay private.
func xraySelectedCheckDiagnostic(result dataplane.NodeCheckResult) string {
	closed := func(value string, allowed ...string) string {
		if value == "" {
			return "none"
		}
		if slices.Contains(allowed, value) {
			return value
		}
		return "unclassified"
	}
	verdict := closed(string(result.Verdict), "PASS", "PARTIAL", "BLOCKED", "MISROUTED", "INCONCLUSIVE", "ERROR")
	stage := closed(result.Stage, "dns", "transport", "configuration", "protocol", "route_identity", "egress", "service", "service_ip", "cleanup", "deadline", "canceled", "resource_scope")
	level := closed(result.TestLevel, "dns", "transport", "protocol", "egress", "service")
	code := closed(result.ErrorCode,
		"node-check-deadline", "node-check-canceled", "node-config-invalid", "node-dns-failed", "node-transport-failed", "node-network-changed", "node-cleanup-failed",
		"node-runtime-config-rejected", "node-protocol-start-failed", "node-route-runtime-changed", "node-route-protocol-mismatch", "node-route-identity-failed",
		"node-egress-control-unavailable", "node-egress-failed", "node-direct-leak", "node-direct-control-unavailable", "node-service-probe-failed",
		"node-service-ip-unavailable", "node-service-ip-path-failed", "node-route-mismatch", "node-service-not-confirmed", "node-resource-refused",
		"node-route-receipt-missing", "node-route-pid-invalid", "node-route-process-unavailable", "node-route-process-stat-invalid", "node-route-engine-mismatch",
		"node-route-network-namespace-mismatch", "node-route-command-unverified", "node-route-config-invalid", "node-route-outbound-missing", "node-route-outbound-ambiguous",
		"node-route-direct-outbound", "node-route-rules-unverified", "node-route-dynamic-config-unverified", "node-route-chain-unverified", "node-route-outbound-unsupported",
		"node-route-remote-endpoint-unverified", "node-route-listener-unsupported", "node-route-listener-unavailable", "node-route-listener-ambiguous", "node-route-listener-owner-unavailable", "node-route-listener-owner-mismatch",
		"request-failed", "response-body-invalid", "route-identity-mismatch", "redirect-host-rejected", "redirect-not-resolved", "unexpected-http-status", "known-block-page",
		"content-type-mismatch", "json-sample-incomplete", "invalid-json", "json-schema-mismatch", "body-predicate-mismatch")
	status := result.HTTPStatus
	if status != 0 && (status < 100 || status > 599) {
		status = -1
	}
	if status >= 100 && result.ErrorCode == fmt.Sprintf("http-%d", status) {
		code = "http-status"
	}
	return fmt.Sprintf("available=%t verdict=%s check_stage=%s error_code=%s http_status=%d direct_leak=%t test_level=%s", result.Available, verdict, stage, code, status, result.DirectLeak, level)
}

// Diagnostic categories are observations only. Never forward raw errors,
// paths or profiles, including text attached to an otherwise known refusal.
func xraySelectedStartupCause(err error) string {
	if err == nil {
		return "none"
	}
	for _, known := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{dataplane.ErrWGOperationOwner, "wg_operation_owner"},
		{operationgate.ErrJournalRecovery, "network_journal_recovery"},
		{operationgate.ErrRecovery, "operation_recovery"}, {operationgate.ErrBusy, "operation_busy"},
		{operationgate.ErrChanged, "operation_changed"},
		{operationgate.ErrSelfUpdateStopped, "control_stopped"}, {operationgate.ErrSelfUpdateStopJournal, "control_journal"},
		{operationgate.ErrSelfUpdateStopChanged, "control_changed"},
		{startuptools.ErrUnknown, "startup_tools"}, {netidentity.ErrUnknown, "network_identity"},
		{dataplane.ErrRuntimeInactivity, "runtime_inactivity"}, {dataplane.ErrNetworkPolicyAuthority, "network_policy_authority"},
		{dataplane.ErrNetworkPolicyConsumers, "network_policy_consumers"},
		{dataplane.ErrXrayRegistration, "xray_registration"}, {app.ErrXrayListSource, "xray_source"},
	} {
		if errors.Is(err, known.err) {
			return known.code
		}
	}
	// These App sentinels are private. Match their complete fixed messages,
	// returning only our fixed category; any added text stays unclassified.
	switch err.Error() {
	case "self update requires matching file/helper recovery":
		return "self_update_recovery"
	case "component update requires reviewed recovery":
		return "component_recovery"
	}
	return "unclassified_refusal"
}

func xraySelectedStartupStageLabel(stage string) string {
	if slices.Contains([]string{
		"constructor", "operation", "control", "network-identity", "startup-tools", "inventory-tools", "backend-inventory", "policy-tools",
		"wg-tools", "wg-tools-identity", "wg-tools-observation", "wg-tools-bind-wireguard", "wg-tools-bind-amneziawg",
		"policy-gate", "state-root", "register-policy", "consumer-checks", "dns-owner", "inactivity-sources",
		"wg-inactivity-sources", "wg-inactivity-sources-wireguard", "wg-inactivity-sources-amneziawg", "wg-inactivity-binding",
	}, stage) {
		return stage
	}
	return "unclassified"
}

func xraySelectedStartupStage(err error) string {
	return xraySelectedStartupStageLabel(app.ManagedListStartupFailureStage(err))
}

func xraySelectedStartupWGSourceStage(err error) string {
	stage := dataplane.WGInactivityReadStage(err)
	if slices.Contains([]string{
		"none", "review-context", "review-lifetime", "review-input", "review-control", "review-adapter", "review-runner", "review-paths", "review-root", "review-source",
		"owner", "context", "lifetime", "adapter-shape", "bound-tools", "identity", "registry", "root", "control-opening", "tools", "control-closing",
	}, stage) {
		return stage
	}
	return "unclassified"
}

func xraySelectedStartupWGToolsStage(err error) string {
	stage := startuptools.WGStartupStage(err)
	if slices.Contains([]string{
		"none", "WG_STARTUP_CONTEXT", "WG_STARTUP_OWNER", "WG_STARTUP_OPEN_CURRENT", "WG_STARTUP_DESCRIPTORS", "WG_STARTUP_CLOSE_CURRENT", "WG_STARTUP_OBSERVATION",
		"WG_INACTIVITY_UNISSUED", "WG_INACTIVITY_DEADLINE", "WG_INACTIVITY_LOCK", "WG_INACTIVITY_ABSENCE", "WG_INACTIVITY_CURRENT", "WG_INACTIVITY_SOURCE",
	}, stage) {
		return stage
	}
	return "unclassified"
}

func xraySelectedStartupInactiveStage(err error) string {
	if err == nil {
		return "none"
	}
	stage := dataplane.RuntimeInactivityBindingStage(err)
	if slices.Contains([]string{"binding-context", "binding-inputs", "binding-settings", "binding-participants", "binding-roots", "binding-already-bound", "binding-dns-settings"}, stage) {
		return stage
	}
	stage = dataplane.NFQWSRuntimeInactiveStage(err)
	if slices.Contains([]string{"source", "platform", "coordinates", "identity", "inventory", "closure"}, stage) {
		return stage
	}
	return "unclassified"
}

func xraySelectedBackendStageLabel(text string) string {
	for _, stage := range []string{"SCOPE", "TOOLS_A", "OPEN_A", "GETGEN_A", "GETTABLE", "TOOLS_B", "CLASSIC", "OPEN_B", "GETGEN_B", "CLOSE"} {
		if text == "network backend inventory refused at "+stage {
			return stage
		}
	}
	return "unclassified"
}

func xraySelectedStartupBackendStage(err error) string {
	if err == nil {
		return "none"
	}
	pending := []error{err}
	labels := []string{}
	for count := 0; len(pending) > 0 && count < 32; count++ {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		// Match the concrete private producer before inspecting its fixed text.
		// Foreign errors with identical text cannot claim this diagnostic stage.
		kind := reflect.TypeOf(current)
		if kind.Kind() == reflect.Pointer && kind.Elem().PkgPath() == "github.com/ArtixSx/razvilka/internal/dataplane" && kind.Elem().Name() == "backendInventoryFailure" {
			label := xraySelectedBackendStageLabel(current.Error())
			if !slices.Contains(labels, label) {
				labels = append(labels, label)
			}
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			pending = append(pending, children[:min(len(children), 32-count-len(pending))]...)
		case interface{ Unwrap() error }:
			if len(pending) < 32-count {
				pending = append(pending, wrapped.Unwrap())
			}
		}
	}
	if len(labels) == 0 {
		return "unclassified"
	}
	return strings.Join(labels, ",")
}

func xraySelectedStartupToolStage(err error) string {
	pending := []error{err}
	stage := "unclassified"
	for count := 0; len(pending) > 0 && count < 32; count++ {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		// Only complete, source-known fixed stages may leave this function.
		for _, known := range []string{"ACQUIRE", "ACQUIRE_IDENTITY", "ACQUIRE_PLATFORM", "UNISSUED", "POLICY_UNISSUED", "POLICY_PLATFORM", "POLICY_ALIAS", "POLICY_ABI"} {
			if current.Error() == "trusted startup tools: "+known {
				stage = known
			}
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			pending = append(pending, children[:min(len(children), 32-count-len(pending))]...)
		case interface{ Unwrap() error }:
			if len(pending) < 32-count {
				pending = append(pending, wrapped.Unwrap())
			}
		}
	}
	return stage
}

type xraySelectedNativeInput struct {
	Root, Profile, Catalog, Sources, Scope string
	HTTPS, Client                          netip.Addr
	Soak                                   bool
}

// Inputs select files and addresses, never health, receipts, process IDs or
// private runtime authority. The native test validates the existing files too.
func xraySelectedParseInput(getenv func(string) string) (xraySelectedNativeInput, error) {
	var in xraySelectedNativeInput
	switch getenv("RAZVILKA_NATIVE_XRAY_SELECTED_SOAK") {
	case "":
	case "1":
		in.Soak = true
	default:
		return in, errors.New("explicit soak opt-in required")
	}
	for key, target := range map[string]*string{
		"ROOT": &in.Root, "PROFILE": &in.Profile, "CATALOG": &in.Catalog, "SOURCES": &in.Sources, "SCOPE": &in.Scope,
	} {
		*target = getenv("RAZVILKA_NATIVE_XRAY_SELECTED_" + key)
		if !filepath.IsAbs(*target) || filepath.Clean(*target) != *target || strings.TrimSpace(*target) != *target || filepath.Dir(*target) == *target {
			return in, errors.New("explicit canonical QA input required")
		}
	}
	var err error
	in.HTTPS, err = netip.ParseAddr(getenv("RAZVILKA_NATIVE_XRAY_SELECTED_HTTPS_IPV4"))
	if err != nil || !in.HTTPS.Is4() || !publicfetch.PublicAddress(in.HTTPS) {
		return in, errors.New("public HTTPS IPv4 required")
	}
	in.Client, err = netip.ParseAddr(getenv("RAZVILKA_NATIVE_XRAY_SELECTED_CLIENT_IPV4"))
	if err != nil || !in.Client.Is4() || !in.Client.IsGlobalUnicast() || in.Client.IsLoopback() {
		return in, errors.New("selected LAN client IPv4 required")
	}
	return in, nil
}

func xraySelectedQAService(pin netip.Addr) catalog.Service {
	cidrs := []string{pin.String() + "/32", xraySelectedTelegramDC2}
	slices.Sort(cidrs)
	return catalog.Service{ID: xraySelectedQAID, Name: "QA Xray selected TCP", Category: "QA", Icon: "+",
		Description: "Separate IPv4 TCP QA definition; not the built-in Telegram service or authenticated Telegram acceptance",
		Domains:     []string{}, CIDRs: slices.Compact(cidrs), Strategy: []string{"xray"}, ProbeURL: "https://telegram.org/",
		Probes: []catalog.Probe{{ID: "qa-https", Label: "Public Telegram HTTPS only", URL: "https://telegram.org/", Required: true,
			Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "none"}}}}
}

// This is intent read from Root's chosen file, not a READY/scope observation.
// Preserve selected device/segment IDs; prohibit broad or unrelated rules.
func xraySelectedScope(data []byte) (*config.NetworkPolicy, error) {
	var p config.NetworkPolicy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(&struct{}{}) != io.EOF || p.Schema != 2 ||
		p.Clients.Mode != "selected_devices" || len(p.Clients.DeviceIDs) != 1 || len(p.Clients.SegmentIDs) != 1 ||
		p.Traffic.Mode != "selected_services" || len(p.Rules) != 0 || p.Exclusions != nil || p.Russian.Enabled {
		return nil, errors.New("one selected device list-only scope intent required")
	}
	p.Revision = 1
	// The actual enabled service and its reviewed node route supply the list
	// selection. Preserve empty rules; a standalone bypass is unsupported by
	// the IP compiler and is not required by the consent API.
	if config.ValidateListNetworkPolicy(&p) != nil {
		return nil, errors.New("invalid scope intent")
	}
	return &p, nil
}

// Never print a response body/raw error: private import/parser errors can carry
// profile material. Only known fixed production refusal codes may be reported.
func xraySelectedRefusal(data []byte) string {
	for _, code := range []string{
		"NODE_HISTORY_ADMISSION_REQUIRED", "NODE_RESOURCE_REFUSED", "NODE_CLEANUP_REQUIRED", "NODE_CHECK_DEADLINE", "NODE_CHECK_CANCELED",
		"NETWORK_POLICY_EXECUTOR_REQUIRED", "NETWORK_POLICY_CONSENT_UNAVAILABLE", "NETWORK_POLICY_PROFILE_OWNER_REQUIRED", "NETWORK_POLICY_SOURCE_UNKNOWN",
		"NETWORK_POLICY_LIST_REQUIRED", "APPLY_REVIEW_CHANGED", "ROUTE_UNAVAILABLE", "SERVICE_RUNTIME_CHANGED", "SERVICE_RUNTIME_CHECK_REQUIRED",
		"SERVICE_RUNTIME_SAFE_MODE", "SERVICE_RUNTIME_UNAVAILABLE", "SERVICE_RUNTIME_UNCONFIGURED", "SERVICE_CONTROL_CHANGED",
		"SERVICE_POLICY_INVALID", "SERVICE_POLICY_CHANGED",
		"NETWORK_POLICY_REVIEW_CHANGED", "NETWORK_POLICY_EXCLUSIONS_SEPARATE", "RESTORE_OPERATION_BUSY", "OPERATION_CANCELED",
		"XRAY_SELECTED_TCP_REVIEW_REFUSED", "XRAY_SELECTED_TCP_REVIEW_REQUIRED", "XRAY_SELECTED_TCP_RUNTIME_REFUSED", "XRAY_SELECTED_TCP_RESPONSE_UNAVAILABLE",
		"NODE_ROUTE_DEPENDENCY", "NODE_REVIEW_CHANGED", "NODE_NETWORK_CHANGED",
		"node-service-ip-path-failed", "node-service-ip-unavailable", "node-service-probe-failed", "node-cleanup-failed", "node-check-deadline",
	} {
		if bytes.Contains(data, []byte(code)) {
			return code
		}
	}
	return "production_refused"
}

func TestXraySelectedClosedConsentRefusals(t *testing.T) {
	for _, code := range []string{"NETWORK_POLICY_REVIEW_CHANGED", "NETWORK_POLICY_EXCLUSIONS_SEPARATE", "RESTORE_OPERATION_BUSY", "OPERATION_CANCELED"} {
		data, err := json.Marshal(map[string]string{"code": code, "error": "private diagnostic must not be returned"})
		if err != nil || xraySelectedRefusal(data) != code {
			t.Fatalf("known consent refusal %q was not preserved", code)
		}
	}
	if got := xraySelectedRefusal([]byte(`{"code":"unknown-private-value","error":"private diagnostic"}`)); got != "production_refused" {
		t.Fatal("unrecognized diagnostics must stay private")
	}
}

func xraySelectedReviewDiagnostic(data []byte) string {
	var body struct {
		Stage   string `json:"review_stage"`
		Cause   string `json:"cause"`
		Elapsed *int64 `json:"elapsed_ms"`
	}
	stage, cause, elapsed := "unclassified", "unclassified", int64(-1)
	if json.Unmarshal(data, &body) == nil {
		switch body.Stage {
		case "target", "admission", "control", "prepare", "final-check", "cleanup":
			stage = body.Stage
		}
		switch body.Cause {
		case "none", "deadline", "canceled", "refused":
			cause = body.Cause
		}
		if body.Elapsed != nil && *body.Elapsed >= 0 && *body.Elapsed <= 120000 {
			elapsed = *body.Elapsed
		}
	}
	return fmt.Sprintf("review_stage=%s cause=%s elapsed_ms=%d", stage, cause, elapsed)
}

func TestXraySelectedReviewDiagnosticKeepsOnlyClosedMetadata(t *testing.T) {
	if got := xraySelectedReviewDiagnostic([]byte(`{"review_stage":"prepare","cause":"deadline","elapsed_ms":12000,"error":"private-profile"}`)); got != "review_stage=prepare cause=deadline elapsed_ms=12000" {
		t.Fatal("known review metadata lost")
	}
	for _, raw := range []string{`{`, `{}`, `{"review_stage":"private-profile","cause":"private-token","elapsed_ms":120001}`, `{"review_stage":{},"elapsed_ms":-1}`} {
		if got := xraySelectedReviewDiagnostic([]byte(raw)); got != "review_stage=unclassified cause=unclassified elapsed_ms=-1" {
			t.Fatal("unrecognized review metadata escaped")
		}
	}
}

func xraySelectedCall(ctx context.Context, client *http.Client, base, token, method, route string, value any) (int, []byte, error) {
	var payload []byte
	var err error
	if value != nil {
		payload, err = json.Marshal(value)
		if err != nil {
			return 0, nil, errors.New("request unavailable")
		}
	}
	defer clear(payload)
	request, err := http.NewRequestWithContext(ctx, method, base+route, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, errors.New("request unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Origin", base)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, errors.New("HTTP operation incomplete")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, xraySelectedMaxResponse+1))
	if err != nil || len(data) > xraySelectedMaxResponse {
		clear(data)
		return response.StatusCode, nil, errors.New("response incomplete or over limit")
	}
	return response.StatusCode, data, nil
}

func TestXraySelectedNativeCatalogAcceptsGenuineStarterAndRejectsQACollision(t *testing.T) {
	actual, err := catalog.Load(filepath.Join("..", "..", "configs", "service-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !xraySelectedCatalogAllowsNewQA(actual) {
		t.Fatal("genuine bundled catalog must allow the separate public QA definition")
	}
	collision := catalog.NFQWS2Starter()
	collision.Services = append(collision.Services, xraySelectedQAService(netip.MustParseAddr("149.154.167.99")))
	if xraySelectedCatalogAllowsNewQA(collision) {
		t.Fatal("existing QA identity must not be replaced or reused")
	}
}

func TestXraySelectedNativeCustomDefinitionUsesOriginalStoreClone(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal("fixture config unavailable")
	}
	path := filepath.Join(root, "custom-services.json")
	custom, err := customservices.Load(path)
	if err != nil {
		t.Fatal("fixture custom store unavailable")
	}
	a := &app.App{Store: store, CustomServices: custom, Catalog: catalog.NFQWS2Starter()}
	input, err := json.Marshal(xraySelectedQAService(netip.MustParseAddr("149.154.167.99")))
	if err != nil {
		t.Fatal("fixture service unavailable")
	}
	response := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/custom-services", bytes.NewReader(input)))
	var created catalog.Service
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil {
		t.Fatal("actual public custom creation failed")
	}
	original := custom.List()
	if len(original) != 1 || original[0].Domains != nil || created.Domains == nil || len(created.Domains) != 0 {
		t.Fatal("actual store/HTTP empty-domain boundary changed")
	}
	created.Domains = nil
	if !reflect.DeepEqual(original, []catalog.Service{created}) {
		t.Fatal("public definition differs beyond the empty-domain representation")
	}
	reopened, err := customservices.Load(path)
	if err != nil || !reflect.DeepEqual(reopened.List(), original) {
		t.Fatal("persisted original definition changed")
	}
	changed := custom.List()[0]
	changed.Probes[0].Expect.StatusCodes[0] = 204
	if _, err := custom.Update(changed.ID, changed); err != nil || reflect.DeepEqual(custom.List(), original) || original[0].Probes[0].Expect.StatusCodes[0] != 200 {
		t.Fatal("actual definition mutation escaped the independent original clone")
	}
}

func TestXraySelectedNativeTCPIntentUsesActualAppliedScopeWithoutAutoEnrollment(t *testing.T) {
	for _, priorApplied := range []bool{false, true} {
		name := "first-unused-service"
		if priorApplied {
			name = "previously-applied-direct-scope"
		}
		t.Run(name, func(t *testing.T) {
			store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal("actual config fixture unavailable")
			}
			service := xraySelectedQAService(netip.MustParseAddr("149.154.167.99"))
			// Model a previous DIRECT configuration through the real Store API.
			// No dataplane process, owned route or native Apply is manufactured.
			if priorApplied {
				if err := store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.41/32"}}); err != nil {
					t.Fatal("prior direct draft unavailable")
				}
				if err := store.ApplyDraft(); err != nil {
					t.Fatal("prior direct configuration commit unavailable")
				}
			}
			nodeID := "node-" + strings.Repeat("a", 64) // Reference only; settings grant no node health.
			if err := store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "xray:" + nodeID, Sources: []string{"192.168.1.40/32"}}); err != nil {
				t.Fatal("desired selected draft unavailable")
			}
			mode := "manual"
			if err := store.UpdateServiceControl(&mode, nil, store.Get().Revision); err != nil {
				t.Fatal("manual control intent unavailable")
			}
			a := &app.App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{service}}}
			handler := a.Handler(http.NotFoundHandler())
			before := store.Get()
			put := func(permission config.ServicePolicy) *httptest.ResponseRecorder {
				t.Helper()
				data, err := json.Marshal(map[string]any{"config_revision": before.Revision, "expected_revision": 0, "policy": permission, "confirm": "SAVE_SERVICE_POLICY"})
				if err != nil {
					t.Fatal("bounded policy request unavailable")
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/v1/service-policies/"+service.ID, bytes.NewReader(data)))
				return response
			}
			wrong := xraySelectedTCPIntent(before, service.ID, nodeID)
			wrong.DeviceSources = slices.Clone(before.Services[service.ID].Sources)
			refused := put(wrong)
			var refusal struct {
				Code string `json:"code"`
			}
			if refused.Code != http.StatusBadRequest || json.Unmarshal(refused.Body.Bytes(), &refusal) != nil || refusal.Code != "SERVICE_POLICY_INVALID" ||
				xraySelectedRefusal(refused.Body.Bytes()) != "SERVICE_POLICY_INVALID" || !reflect.DeepEqual(store.Get(), before) {
				t.Fatal("draft scope was accepted or actual applied-scope refusal changed")
			}
			permission := xraySelectedTCPIntent(before, service.ID, nodeID)
			accepted := put(permission)
			var result struct {
				OK          bool                 `json:"ok"`
				LiveApplied bool                 `json:"live_applied"`
				Policy      config.ServicePolicy `json:"policy"`
			}
			if accepted.Code != http.StatusOK || json.Unmarshal(accepted.Body.Bytes(), &result) != nil || !result.OK || result.LiveApplied {
				t.Fatalf("actual applied-scope manual policy refused: status=%d", accepted.Code)
			}
			after := store.Get()
			p := after.ServicePolicies[service.ID]
			if p.Revision != 1 || after.Revision != before.Revision+1 || p.Mode != "manual" || !p.Enabled || p.PinFallback || p.LegacyOptIn || p.GroupID != "" ||
				p.PinnedNodeID != nodeID || !slices.Equal(p.AllowedNodeIDs, []string{nodeID}) || !slices.Equal(p.AllowedEngines, []string{"xray"}) ||
				p.Scenario != (config.ServiceScenario{Kind: "web"}) || !reflect.DeepEqual(p.DeviceSources, before.AppliedServices[service.ID].Sources) ||
				!reflect.DeepEqual(before.Services, after.Services) || !reflect.DeepEqual(before.AppliedServices, after.AppliedServices) ||
				before.AppliedRevision != after.AppliedRevision || !reflect.DeepEqual(before.ServiceControl, after.ServiceControl) ||
				!reflect.DeepEqual(before.NetworkPolicy, after.NetworkPolicy) || !reflect.DeepEqual(before.DefaultRouteConsent, after.DefaultRouteConsent) {
				t.Fatal("manual TCP/IPv4 intent changed scope, applied state or automatic enrollment")
			}
			stale := put(permission)
			if stale.Code != http.StatusConflict || json.Unmarshal(stale.Body.Bytes(), &refusal) != nil || refusal.Code != "SERVICE_POLICY_CHANGED" ||
				xraySelectedRefusal(stale.Body.Bytes()) != "SERVICE_POLICY_CHANGED" || !reflect.DeepEqual(store.Get(), after) {
				t.Fatal("service policy revision fence was bypassed")
			}
		})
	}
}

func TestXraySelectedNativeStartupDiagnosticsKeepPrivateCausesClosed(t *testing.T) {
	const secret = "vless://UUID:PRIVATE-KEY@private.invalid/"
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, "none"}, {errors.Join(errors.New(secret), operationgate.ErrBusy), "operation_busy"},
		{errors.Join(errors.New(secret), dataplane.ErrWGOperationOwner), "wg_operation_owner"},
		{errors.Join(dataplane.ErrWGOperationOwner, context.DeadlineExceeded), "deadline"},
		{errors.Join(dataplane.ErrWGOperationOwner, context.Canceled), "canceled"},
		{errors.New(dataplane.ErrWGOperationOwner.Error()), "unclassified_refusal"},
		{errors.Join(errors.New(secret), startuptools.ErrUnknown), "startup_tools"},
		{errors.New("self update requires matching file/helper recovery"), "self_update_recovery"},
		{errors.New("self update requires matching file/helper recovery: " + secret), "unclassified_refusal"},
		{errors.New(secret), "unclassified_refusal"},
	} {
		if got := xraySelectedStartupCause(test.err); got != test.want {
			t.Fatal("unexpected fixed startup category", got)
		}
	}
	if got := xraySelectedStartupToolStage(errors.Join(errors.New(secret), errors.New("trusted startup tools: ACQUIRE"))); got != "ACQUIRE" {
		t.Fatal("known tool stage hidden", got)
	}
	if got := xraySelectedStartupToolStage(errors.New("trusted startup tools: ACQUIRE " + secret)); got != "unclassified" {
		t.Fatal("arbitrary tool diagnostic text escaped allowlist", got)
	}
	_, inactiveErr := dataplane.NewNFQWSRuntimeInactiveSource(context.Background(), nil, nil)
	if got := xraySelectedStartupInactiveStage(errors.Join(context.DeadlineExceeded, errors.New(secret), inactiveErr)); got != "source" {
		t.Fatal("actual nested inactivity source stage hidden")
	}
	if xraySelectedStartupInactiveStage(nil) != "none" || xraySelectedStartupBackendStage(nil) != "none" || xraySelectedStartupInactiveStage(errors.New("NFQWS runtime inactivity: source")) != "unclassified" {
		t.Fatal("absent or forged inactivity stage misclassified")
	}
	for _, stage := range []string{"SCOPE", "TOOLS_A", "OPEN_A", "GETGEN_A", "GETTABLE", "TOOLS_B", "CLASSIC", "OPEN_B", "GETGEN_B", "CLOSE"} {
		text := "network backend inventory refused at " + stage
		if xraySelectedBackendStageLabel(text) != stage || xraySelectedBackendStageLabel(text+" "+secret) != "unclassified" || xraySelectedStartupBackendStage(errors.Join(context.DeadlineExceeded, errors.New(text))) != "unclassified" {
			t.Fatal("backend label privacy or concrete-type check failed")
		}
	}
	wide := make([]error, 128)
	for i := range wide {
		wide[i] = errors.New(secret)
	}
	if xraySelectedStartupBackendStage(errors.Join(wide...)) != "unclassified" {
		t.Fatal("foreign nested errors escaped bounded diagnostic traversal")
	}
}

func TestXraySelectedNativeStartupInactivityBindingKeepsOriginalContextCause(t *testing.T) {
	for _, change := range []string{"deadline", "cancelled", "unbounded", "inputs"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			end := func() {}
			wantCause, wantStage := "runtime_inactivity", "binding-context"
			switch change {
			case "deadline":
				ctx, end = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				wantCause = "deadline"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "inputs":
				ctx, end = context.WithTimeout(ctx, time.Minute)
				wantStage = "binding-inputs"
			}
			defer end()
			if change == "cancelled" {
				wantCause = "canceled"
			}
			err := dataplane.New(t.TempDir()).BindRuntimeInactivitySources(ctx, nil, nil, "")
			if xraySelectedStartupCause(err) != wantCause || xraySelectedStartupInactiveStage(err) != wantStage {
				t.Fatal("Main startup diagnostics hid original binding cause or coordinate", xraySelectedStartupCause(err), xraySelectedStartupInactiveStage(err))
			}
		})
	}
	if xraySelectedStartupInactiveStage(errors.New("runtime inactivity binding refused at binding-context")) != "unclassified" {
		t.Fatal("untyped text fabricated original binding evidence")
	}
}

type xraySelectedWGDiagnosticCycle struct{}

func (*xraySelectedWGDiagnosticCycle) Error() string {
	panic("WG diagnostic must not read foreign error text")
}
func (e *xraySelectedWGDiagnosticCycle) Unwrap() error { return e }

func TestXraySelectedNativeWGStartupDiagnosticsKeepTypedStagesClosed(t *testing.T) {
	marker := "vless://UUID:PRIVATE-KEY@private.invalid/" + strings.Repeat("PRIVATE", 6000)
	_, sourceErr := dataplane.ReviewWGInactivityRead(nil, nil, nil, nil, dataplane.WGCommandTools{})
	var lease *startuptools.Lease
	_, contextErr := lease.ManagedListWGCommandTools(nil, netidentity.Identity{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, unissuedErr := lease.ReviewWGInactivity(ctx, nil, nil, "wireguard")
	for _, test := range []struct {
		err           error
		source, tools string
	}{
		{nil, "none", "none"},
		{sourceErr, "review-context", "unclassified"},
		{contextErr, "unclassified", "WG_STARTUP_CONTEXT"},
		{unissuedErr, "unclassified", "WG_INACTIVITY_UNISSUED"},
		{errors.Join(contextErr, sourceErr), "review-context", "WG_STARTUP_CONTEXT"},
	} {
		err := test.err
		if err != nil {
			err = errors.Join(errors.New(marker), fmt.Errorf("private wrapper: %w", errors.Join(err, context.DeadlineExceeded)))
		}
		if xraySelectedStartupWGSourceStage(err) != test.source || xraySelectedStartupWGToolsStage(err) != test.tools {
			t.Fatal("actual nested typed WG stage hidden or widened")
		}
		if test.err == nil {
			continue
		}
		for _, text := range []string{test.err.Error(), test.err.Error() + marker, marker} {
			spoof := errors.New(text)
			if xraySelectedStartupWGSourceStage(spoof) != "unclassified" || xraySelectedStartupWGToolsStage(spoof) != "unclassified" {
				t.Fatal("foreign WG diagnostic text escaped the typed projection")
			}
		}
	}
	cycle := &xraySelectedWGDiagnosticCycle{}
	if xraySelectedStartupWGSourceStage(cycle) != "unclassified" || xraySelectedStartupWGToolsStage(cycle) != "unclassified" {
		t.Fatal("cyclic foreign diagnostic escaped the bounded typed walk")
	}
	wide := make([]error, 128)
	for i := range wide {
		wide[i] = errors.New(marker)
	}
	wide[len(wide)-1] = sourceErr
	if xraySelectedStartupWGSourceStage(errors.Join(wide...)) != "unclassified" {
		t.Fatal("WG source diagnostic exceeded its bounded walk")
	}
	wide[len(wide)-1] = contextErr
	if xraySelectedStartupWGToolsStage(errors.Join(wide...)) != "unclassified" {
		t.Fatal("WG tool diagnostic exceeded its bounded walk")
	}
}

func TestXraySelectedNativeStartupStagesRejectDynamicMarkers(t *testing.T) {
	const marker = "vless://UUID:PRIVATE-KEY@private.invalid/"
	for _, stage := range []string{
		"constructor", "operation", "control", "network-identity", "startup-tools", "inventory-tools", "backend-inventory", "policy-tools",
		"wg-tools", "wg-tools-identity", "wg-tools-observation", "wg-tools-bind-wireguard", "wg-tools-bind-amneziawg",
		"policy-gate", "state-root", "register-policy", "consumer-checks", "dns-owner", "inactivity-sources",
		"wg-inactivity-sources", "wg-inactivity-sources-wireguard", "wg-inactivity-sources-amneziawg", "wg-inactivity-binding",
	} {
		if xraySelectedStartupStageLabel(stage) != stage || xraySelectedStartupStageLabel(stage+marker) != "unclassified" {
			t.Fatal("startup stage changed or dynamic marker escaped allowlist")
		}
	}
	for _, stage := range []string{"", marker, "wg-tools-bind-foreign", "wg-inactivity-sources-foreign", "wg-inactivity-sources-wireguard " + marker} {
		if xraySelectedStartupStageLabel(stage) != "unclassified" {
			t.Fatal("unknown engine or startup stage escaped allowlist")
		}
	}
	if xraySelectedStartupStage(nil) != "constructor" || xraySelectedStartupStage(errors.New(marker)) != "constructor" {
		t.Fatal("foreign error manufactured a typed App startup stage")
	}
}

func TestXraySelectedNativeCheckDiagnosticKeepsTypedFieldsClosed(t *testing.T) {
	result := dataplane.NodeCheckResult{Available: false, Verdict: "ERROR", Stage: "service_ip", ErrorCode: "node-service-ip-path-failed", HTTPStatus: 200, TestLevel: "service"}
	if got := xraySelectedCheckDiagnostic(result); got != "available=false verdict=ERROR check_stage=service_ip error_code=node-service-ip-path-failed http_status=200 direct_leak=false test_level=service" {
		t.Fatal("known typed check diagnostic changed")
	}
	result.ErrorCode, result.HTTPStatus = "http-503", 503
	if !strings.Contains(xraySelectedCheckDiagnostic(result), "error_code=http-status http_status=503") {
		t.Fatal("bounded HTTP refusal category lost")
	}
	for _, secret := range []string{"vless://UUID:PRIVATE-KEY@private.invalid/", "node-service-ip-path-failed private.invalid", strings.Repeat("PRIVATE-KEY", 4096)} {
		result := dataplane.NodeCheckResult{Available: true, Verdict: evidence.Verdict(secret), Stage: secret, ErrorCode: secret, HTTPStatus: 1 << 30, DirectLeak: true, TestLevel: secret,
			NodeID: secret, ServiceID: secret, RoutePathID: secret, NetworkProfile: secret, EgressIP: secret, Message: secret, DirectControl: secret}
		if got := xraySelectedCheckDiagnostic(result); got != "available=true verdict=unclassified check_stage=unclassified error_code=unclassified http_status=-1 direct_leak=true test_level=unclassified" {
			t.Fatal("unknown diagnostic fields escaped the closed projection")
		}
	}
}

func TestXraySelectedNativeInputAndScopeRejectWidening(t *testing.T) {
	root := filepath.Join(t.TempDir(), "qa")
	values := map[string]string{"ROOT": root, "PROFILE": filepath.Join(root, "selected-profile"), "CATALOG": filepath.Join(root, "catalog.json"),
		"SOURCES": filepath.Join(root, "sources.json"), "SCOPE": filepath.Join(root, "scope.json"), "HTTPS_IPV4": "149.154.167.99", "CLIENT_IPV4": "192.168.1.100"}
	get := func(key string) string { return values[strings.TrimPrefix(key, "RAZVILKA_NATIVE_XRAY_SELECTED_")] }
	if _, err := xraySelectedParseInput(get); err != nil {
		t.Fatal("valid path/address contract rejected")
	}
	for _, key := range []string{"PROFILE", "HTTPS_IPV4", "CLIENT_IPV4"} {
		old := values[key]
		values[key] = "vless://UUID:PRIVATE-KEY@private.invalid/"
		if _, err := xraySelectedParseInput(get); err == nil {
			t.Fatal("invalid path/address accepted")
		}
		values[key] = old
	}
	p := config.NetworkPolicy{Schema: 2, Clients: config.ClientScope{Mode: "selected_devices", SegmentIDs: []string{"actual-segment-id"}, DeviceIDs: []string{"actual-device-id"}, NewDevices: "base"},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	data, _ := json.Marshal(p)
	approved, err := xraySelectedScope(data)
	if err != nil || len(approved.Rules) != 0 || approved.Revision != 1 || !reflect.DeepEqual(approved.Clients, p.Clients) || approved.Traffic != p.Traffic {
		t.Fatal("one-device list intent changed or gained a standalone rule")
	}
	for _, cut := range []string{"all-except", "multiple-devices", "unrelated-rule", "ready-dto"} {
		changed := config.CloneNetworkPolicy(&p)
		switch cut {
		case "all-except":
			changed.Traffic.Mode = "all_except"
		case "multiple-devices":
			changed.Clients.DeviceIDs = append(changed.Clients.DeviceIDs, "second-device")
		case "unrelated-rule":
			changed.Rules = []config.NetworkRule{{Kind: "cidr", Value: "0.0.0.0/0"}}
		}
		data, _ := json.Marshal(changed)
		if cut == "ready-dto" {
			data = append(data[:len(data)-1], []byte(`,"ready":true}`)...)
		}
		if _, err := xraySelectedScope(data); err == nil {
			t.Fatal("scope widening or runtime DTO accepted", cut)
		}
	}
	service := xraySelectedQAService(netip.MustParseAddr(values["HTTPS_IPV4"]))
	if len(service.Domains) != 0 || len(service.CIDRs) != 2 || service.ID == "telegram" || service.ProbeURL != "https://telegram.org/" || catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}) != nil {
		t.Fatal("QA definition replaced built-in domains or widened its destinations")
	}
}

func TestXraySelectedNativeHTTPBoundsAndRefusalPrivacy(t *testing.T) {
	const secret = "vless://UUID:PRIVATE-KEY@private.invalid/"
	for _, body := range []string{secret, `{"error":"` + secret + `","code":"PRIVATE-KEY"}`, `{"code":"NODE_HISTORY_ADMISSION_REQUIRED","error":"` + secret + `"}`} {
		code := xraySelectedRefusal([]byte(body))
		if strings.Contains(code, "PRIVATE") || strings.Contains(code, "UUID") || strings.Contains(code, "://") {
			t.Fatal("refusal output exposed raw material")
		}
	}
	if xraySelectedRefusal([]byte("NETWORK_POLICY_EXECUTOR_REQUIRED: existing route unchanged")) != "NETWORK_POLICY_EXECUTOR_REQUIRED" {
		t.Fatal("current production blocker was hidden")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-test-token" || r.Header.Get("Origin") == "" {
			t.Error("authenticated request contract lost")
		}
		_, _ = io.WriteString(w, strings.Repeat("x", xraySelectedMaxResponse+1))
	}))
	defer server.Close()
	status, data, err := xraySelectedCall(context.Background(), server.Client(), server.URL, "owned-test-token", "POST", "/fixture", map[string]string{"profile": secret})
	if status != 200 || data != nil || err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unbounded response or raw request data escaped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := xraySelectedCall(ctx, server.Client(), server.URL, "owned-test-token", "GET", "/fixture", nil); err == nil {
		t.Fatal("canceled HTTP request completed")
	}
}
