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
	p.Rules = []config.NetworkRule{{ID: "qa-selected-tcp", Revision: 1, Kind: "service", Value: xraySelectedQAID, Action: "bypass"}}
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
		"node-service-ip-path-failed", "node-service-ip-unavailable", "node-service-probe-failed", "node-cleanup-failed", "node-check-deadline",
	} {
		if bytes.Contains(data, []byte(code)) {
			return code
		}
	}
	return "production_refused"
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

func TestXraySelectedNativeStartupDiagnosticsKeepPrivateCausesClosed(t *testing.T) {
	const secret = "vless://UUID:PRIVATE-KEY@private.invalid/"
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, "none"}, {errors.Join(errors.New(secret), operationgate.ErrBusy), "operation_busy"},
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
	if err != nil || len(approved.Rules) != 1 || approved.Rules[0].Value != xraySelectedQAID {
		t.Fatal("one-device intent did not retain its exact QA rule")
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
