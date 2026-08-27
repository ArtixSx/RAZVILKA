package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/profileexchange"
	"github.com/ArtixSx/razvilka/internal/routerstats"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/smartroute"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/telemetry"
	"github.com/ArtixSx/razvilka/internal/testlab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type confirmedRouteProber struct{}

type deviceRunner struct{ output string }

type strategyValidator struct{}

func (strategyValidator) Validate(_ context.Context, arguments []string) strategylab.Validation {
	return strategylab.Validation{OK: true, Native: true, Code: "PASS", Arguments: arguments}
}

type strategyProbeExecutor struct{}

func TestClassifyWARPHandshakeFailure(t *testing.T) {
	failure := classifyApplyFailure("WARP WireGuard handshake was not confirmed on UDP ports 2408, 500, 1701, 4500")
	if failure.Code != "WARP_WIREGUARD_HANDSHAKE" || !failure.DraftPreserved || !failure.Retryable {
		t.Fatalf("unexpected failure advice: %+v", failure)
	}
	if len(failure.Alternatives) != 3 || !strings.Contains(failure.Resolution, "AmneziaWG") {
		t.Fatalf("missing safe alternatives: %+v", failure)
	}

	legacy := classifyApplyFailure("WARP handshake was not confirmed: peer handshake timestamp is zero")
	if legacy.Code != "WARP_WIREGUARD_HANDSHAKE" {
		t.Fatalf("legacy WARP failure was not classified: %+v", legacy)
	}
}

func TestDNSProfileAPIKeepsChangesDraftOnly(t *testing.T) {
	manager, err := dnscontrol.New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{DNS: manager}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/dns/draft", strings.NewReader(`{"profile_id":"ad-block"}`))
	response := httptest.NewRecorder()
	a.dnsDraft(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("draft status=%d body=%s", response.Code, response.Body.String())
	}
	var snapshot dnscontrol.Snapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Dirty || snapshot.Draft.ProfileID != "ad-block" || snapshot.Applied.ProfileID != "automatic" || snapshot.Mode != "preview" {
		t.Fatalf("DNS API claimed a live change: %+v", snapshot)
	}
	status := httptest.NewRecorder()
	a.dnsStatus(status, httptest.NewRequest(http.MethodGet, "/api/v1/dns", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"mode":"preview"`) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
}

func TestDNSApplyExplainsMissingLiveAdapterAndPreservesDraft(t *testing.T) {
	manager, err := dnscontrol.New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetDraft("ad-block"); err != nil {
		t.Fatal(err)
	}
	a := &App{DNS: manager}
	response := httptest.NewRecorder()
	a.dnsApply(response, httptest.NewRequest(http.MethodPost, "/api/v1/dns/apply", nil))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"DNS_LIVE_ADAPTER_UNAVAILABLE"`) || !strings.Contains(response.Body.String(), `"draft_preserved":true`) {
		t.Fatalf("DNS apply response=%d body=%s", response.Code, response.Body.String())
	}
	if !manager.Snapshot().Dirty {
		t.Fatal("blocked DNS apply discarded the draft")
	}
}

func TestStatusIncludesIndependentDNSDraft(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := dnscontrol.New(filepath.Join(root, "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetDraft("security"); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, DNS: manager, Start: time.Now()}
	response := httptest.NewRecorder()
	a.status(response, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"dns_pending_changes":true`) || !strings.Contains(response.Body.String(), `"pending_changes":true`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNextDNSProfileAPIValidatesAndStaysLocal(t *testing.T) {
	manager, err := dnscontrol.New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{DNS: manager}
	invalid := httptest.NewRecorder()
	a.dnsNextDNS(invalid, httptest.NewRequest(http.MethodPut, "/api/v1/dns/nextdns", strings.NewReader(`{"profile_id":"not-valid"}`)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	response := httptest.NewRecorder()
	a.dnsNextDNS(response, httptest.NewRequest(http.MethodPut, "/api/v1/dns/nextdns", strings.NewReader(`{"profile_id":"a1b2c3"}`)))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"nextdns_profile_id":"a1b2c3"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if manager.Snapshot().Applied.ProfileID != "automatic" {
		t.Fatal("NextDNS setup changed applied DNS")
	}
}

func TestCustomDNSAPIValidatesAndDoesNotApply(t *testing.T) {
	manager, err := dnscontrol.New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{DNS: manager}
	invalid := httptest.NewRecorder()
	a.dnsCustom(invalid, httptest.NewRequest(http.MethodPut, "/api/v1/dns/custom", strings.NewReader(`{"doh":"http://dns.example/query"}`)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	response := httptest.NewRecorder()
	a.dnsCustom(response, httptest.NewRequest(http.MethodPut, "/api/v1/dns/custom", strings.NewReader(`{"name":"Home","servers":["9.9.9.9"],"doh":"https://dns.example/dns-query"}`)))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"custom"`) || !strings.Contains(response.Body.String(), `"9.9.9.9:53"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if manager.Snapshot().Applied.ProfileID != "automatic" {
		t.Fatal("custom DNS API changed applied selection")
	}
	deleted := httptest.NewRecorder()
	a.dnsCustom(deleted, httptest.NewRequest(http.MethodDelete, "/api/v1/dns/custom", nil))
	if deleted.Code != http.StatusOK || strings.Contains(deleted.Body.String(), `"name":"Home"`) {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestProviderProfilePreviewAndImportStayDraftOnly(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	a := &App{EngineConfigs: configs}
	const uri = "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=reality&sni=front.example&pbk=PUBLIC_KEY&type=tcp#Home"

	previewBody, _ := json.Marshal(map[string]string{"uri": uri})
	preview := httptest.NewRecorder()
	a.providerProfilePreview(preview, httptest.NewRequest(http.MethodPost, "/api/v1/provider-profiles/preview", bytes.NewReader(previewBody)))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"node_count":1`) || strings.Contains(preview.Body.String(), "123e4567") || strings.Contains(preview.Body.String(), "PUBLIC_KEY") {
		t.Fatalf("preview status=%d leaked profile: %s", preview.Code, preview.Body.String())
	}
	if content, err := configs.Read("sing-box", "main"); err != nil || content.Source != "missing" {
		t.Fatalf("preview wrote a draft: %+v err=%v", content, err)
	}

	missingConfirm := httptest.NewRecorder()
	a.providerProfileImport(missingConfirm, httptest.NewRequest(http.MethodPost, "/api/v1/provider-profiles/import", bytes.NewReader(previewBody)))
	if missingConfirm.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing confirmation status=%d body=%s", missingConfirm.Code, missingConfirm.Body.String())
	}

	importBody, _ := json.Marshal(map[string]string{"uri": uri, "confirm": "IMPORT_REMOTE_PROFILE"})
	imported := httptest.NewRecorder()
	a.providerProfileImport(imported, httptest.NewRequest(http.MethodPost, "/api/v1/provider-profiles/import", bytes.NewReader(importBody)))
	if imported.Code != http.StatusOK || !strings.Contains(imported.Body.String(), `"draft_only":true`) {
		t.Fatalf("import status=%d body=%s", imported.Code, imported.Body.String())
	}
	content, err := configs.ReadExpert("sing-box", "main")
	if err != nil || content.Source != "staged" || !strings.Contains(content.Content, "PUBLIC_KEY") {
		t.Fatalf("sing-box draft=%+v err=%v", content, err)
	}
}

func TestProviderProfileImportHonorsExplicitNodeSelection(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	a := &App{EngineConfigs: configs}
	profile := "vless://123e4567-e89b-12d3-a456-426614174000@one.example:443?security=tls#One\n" +
		"hysteria2://secret@two.example:8443?sni=front.example#Two"
	body, _ := json.Marshal(map[string]any{"profile": profile, "confirm": "IMPORT_REMOTE_PROFILE", "selected_index": 1})
	response := httptest.NewRecorder()
	a.providerProfileImport(response, httptest.NewRequest(http.MethodPost, "/api/v1/provider-profiles/import", bytes.NewReader(body)))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"selected_index":1`) {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	content, err := configs.ReadExpert("sing-box", "main")
	if err != nil || !strings.Contains(content.Content, `"default": "node-02"`) {
		t.Fatalf("selected node was not staged: %+v err=%v", content, err)
	}
}

func TestClassifyWARPMASQUEServiceTimeout(t *testing.T) {
	failure := classifyApplyFailure(`usque probe for Telegram failed: Get "https://telegram.org/": context deadline exceeded`)
	if failure.Code != "WARP_MASQUE_SERVICE_TIMEOUT" || !failure.DraftPreserved || !failure.Retryable {
		t.Fatalf("unexpected failure advice: %+v", failure)
	}
	if len(failure.Alternatives) != 3 || !strings.Contains(failure.Resolution, "Sing-box") {
		t.Fatalf("missing non-WARP alternatives: %+v", failure)
	}
}

func TestClassifyUSQUETransportCanaryKeepsHelpfulAdvice(t *testing.T) {
	failure := classifyApplyExecutionFailure(`usque candidate transports failed: QUIC: candidate probe for Telegram failed: context deadline exceeded; HTTP/2: candidate probe for Telegram failed: context deadline exceeded`, "canary-failed")
	if failure.Code != "WARP_MASQUE_SERVICE_TIMEOUT" || !strings.Contains(failure.Message, "не изменялись") {
		t.Fatalf("unexpected transport advice: %+v", failure)
	}
}

func TestClassifyApplyFailureExplainsTimeoutAndRollback(t *testing.T) {
	failure := classifyApplyFailure("stage nfqws2: context deadline exceeded")
	if failure.Code != "DATAPLANE_OPERATION_CANCELLED" || !failure.DraftPreserved || !strings.Contains(strings.ToLower(failure.Message), "rollback") {
		t.Fatalf("timeout advice = %+v", failure)
	}
}

func TestClassifyCanaryFailureSaysLiveRouteWasUntouched(t *testing.T) {
	failure := classifyApplyExecutionFailure("sing-box candidate probe for Telegram failed", "canary-failed")
	if failure.Code != "CANARY_FAILED" || !strings.Contains(failure.Message, "не изменялись") || !failure.DraftPreserved || !failure.Retryable {
		t.Fatalf("unexpected canary advice: %+v", failure)
	}
}

func TestStaticUIIsNeverServedFromAnOldRouterCache(t *testing.T) {
	a := &App{}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	a.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ui"))
	})).ServeHTTP(response, request)

	if got := response.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("static UI cache policy = %q, want no-store", got)
	}
	if got := response.Header().Get("X-RAZVILKA-UI-Version"); got != Version {
		t.Fatalf("static UI version header = %q, want %q", got, Version)
	}
}

func (strategyProbeExecutor) Execute(_ context.Context, candidate strategylab.Candidate, target strategylab.ProbeTarget) (strategylab.Evidence, error) {
	return strategylab.Evidence{CandidateID: candidate.ID, ServiceID: target.ServiceID, Protocol: target.Protocol, IPFamily: target.IPFamily, Success: true, RouteConfirmed: true, LatencyMS: 9, Stages: []strategylab.StageEvidence{{Stage: "route", Status: "pass"}}}, nil
}

func TestStrategyLabCandidateAPIStaysDraftOnly(t *testing.T) {
	manager, err := strategylab.New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{StrategyLab: manager}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/strategy-lab/candidates", strings.NewReader(`{"pool_id":"tcp-tls","name":"TLS","arguments":"--filter-tcp=443 --payload=tls_client_hello"}`))
	response := httptest.NewRecorder()
	a.strategyLabCandidates(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create candidate status=%d body=%s", response.Code, response.Body.String())
	}
	snapshotResponse := httptest.NewRecorder()
	a.strategyLabSnapshot(snapshotResponse, httptest.NewRequest(http.MethodGet, "/api/v1/strategy-lab", nil))
	var snapshot strategylab.Snapshot
	if err := json.NewDecoder(snapshotResponse.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Candidates) != 1 || snapshot.Safety["live_config_changed"] != false {
		t.Fatalf("unexpected Strategy Lab snapshot: %+v", snapshot)
	}

	unsafeResponse := httptest.NewRecorder()
	a.strategyLabCandidates(unsafeResponse, httptest.NewRequest(http.MethodPost, "/api/v1/strategy-lab/candidates", strings.NewReader(`{"pool_id":"tcp-tls","name":"unsafe","arguments":"--filter-tcp=443; reboot"}`)))
	if unsafeResponse.Code != http.StatusBadRequest {
		t.Fatalf("unsafe candidate status=%d", unsafeResponse.Code)
	}

	deleteResponse := httptest.NewRecorder()
	a.strategyLabCandidateAction(deleteResponse, httptest.NewRequest(http.MethodDelete, "/api/v1/strategy-lab/candidates/"+snapshot.Candidates[0].ID, strings.NewReader(`{}`)))
	if deleteResponse.Code != http.StatusOK || len(manager.Snapshot().Candidates) != 0 {
		t.Fatalf("candidate delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
}

func TestStrategyLabProbeUsesCatalogURLAndRecordsEvidence(t *testing.T) {
	manager, err := strategylab.New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.Validator = strategyValidator{}
	manager.Executor = strategyProbeExecutor{}
	candidate, err := manager.AddCandidate("tcp-tls", "TLS", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Validate(context.Background(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	a := &App{StrategyLab: manager, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video", Category: "Test", Strategy: []string{"nfqws2"}, Domains: []string{"example.com"}, ProbeURL: "https://example.com/"}}}}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/strategy-lab/candidates/"+candidate.ID+"/probe", strings.NewReader(`{"service_id":"video","ip_family":"ipv4"}`))
	a.strategyLabCandidateAction(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"route_confirmed":true`) {
		t.Fatalf("probe status=%d body=%s", response.Code, response.Body.String())
	}
	if len(manager.Snapshot().Evidence) != 1 {
		t.Fatal("probe evidence was not persisted")
	}

	unknown := httptest.NewRecorder()
	a.strategyLabCandidateAction(unknown, httptest.NewRequest(http.MethodPost, "/api/v1/strategy-lab/candidates/"+candidate.ID+"/probe", strings.NewReader(`{"service_id":"not-in-catalog","probe_url":"https://attacker.invalid/"}`)))
	if unknown.Code != http.StatusBadRequest || len(manager.Snapshot().Evidence) != 1 {
		t.Fatalf("browser supplied target was accepted: status=%d", unknown.Code)
	}
}

func TestZ2KStrategyImportIsExplicitAtomicAndDraftOnly(t *testing.T) {
	root := t.TempDir()
	strategyDir := filepath.Join(root, "lists", "custom-strategies")
	if err := os.MkdirAll(strategyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".z2k-installed-tag"), []byte("v2.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(strategyDir, "yt_tcp.txt"), []byte("--filter-tcp=443 --payload=tls_client_hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := strategylab.New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{StrategyLab: manager, Z2KRoot: root}

	missingConfirmation := httptest.NewRecorder()
	a.z2kMigrationImportStrategies(missingConfirmation, httptest.NewRequest(http.MethodPost, "/api/v1/migrations/z2k/import-strategies", strings.NewReader(`{"confirm":""}`)))
	if missingConfirmation.Code != http.StatusBadRequest || len(manager.Snapshot().Candidates) != 0 {
		t.Fatalf("unconfirmed import changed state: status=%d", missingConfirmation.Code)
	}

	response := httptest.NewRecorder()
	a.z2kMigrationImportStrategies(response, httptest.NewRequest(http.MethodPost, "/api/v1/migrations/z2k/import-strategies", strings.NewReader(`{"confirm":"IMPORT_Z2K_STRATEGIES"}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	snapshot := manager.Snapshot()
	if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].Origin != "z2k:v2.0.1:lists/custom-strategies/yt_tcp.txt" || snapshot.Candidates[0].Validation.OK {
		t.Fatalf("unexpected imported candidate: %+v", snapshot.Candidates)
	}
	if !strings.Contains(response.Body.String(), `"live_config_changed":false`) || !strings.Contains(response.Body.String(), `"draft_only":true`) {
		t.Fatalf("import safety flags missing: %s", response.Body.String())
	}
}

func TestMetricsEndpointReturnsBoundedHistoryAndCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	stats := routerstats.New(routerstats.Collector{
		Now: func() time.Time { now = now.Add(time.Second); return now },
		DiskProbe: func(string) (uint64, uint64, error) {
			return 512 << 20, 256 << 20, nil
		},
	})
	stats.Sample()
	stats.Sample()
	a := &App{Stats: stats}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/metrics?limit=1", nil)
	response := httptest.NewRecorder()
	a.metrics(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		History           []routerstats.Snapshot      `json:"history"`
		Capacity          routerstats.Capacity        `json:"capacity"`
		TrafficPeriods    []routerstats.TrafficPeriod `json:"traffic_periods"`
		HistoryPersistent bool                        `json:"history_persistent"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.History) != 1 || len(result.TrafficPeriods) != 3 || result.HistoryPersistent {
		t.Fatalf("unexpected metrics response: %+v", result)
	}

	bad := httptest.NewRecorder()
	a.metrics(bad, httptest.NewRequest(http.MethodGet, "/api/v1/metrics?limit=721", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status=%d", bad.Code)
	}
}

func TestApplicationUpdateEndpoint(t *testing.T) {
	releases := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.9.0","html_url":"https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.9.0","published_at":"2026-08-14T10:00:00Z"}`))
	}))
	defer releases.Close()
	manager := updatecheck.New("0.8.0")
	manager.Endpoint, manager.Client = releases.URL, releases.Client()
	a := &App{Updates: manager}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/update?refresh=true", nil)
	response := httptest.NewRecorder()
	a.updateStatus(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var result updatecheck.Result
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.UpdateAvailable || result.LatestVersion != "0.9.0" {
		t.Fatalf("unexpected update response: %+v", result)
	}
}

func TestStatusDoesNotClaimCommittedPlanIsLiveWithoutRuntimeEvidence(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	plan, err := dataplane.BuildAt(dataplane.Input{
		Revision: 1,
		Routes:   []dataplane.Route{{ServiceID: "youtube", Resolved: "nfqws2"}},
		Engines:  []dataplane.Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}},
		Host:     dataplane.HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	if err := manager.Record(plan); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{}, Dataplane: manager, Start: time.Now()}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	a.status(response, request)
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["live_active"] == true {
		t.Fatalf("stored plan was presented as live without recovery/execution evidence: %v", result)
	}
}

func TestStatusCountsOnlyEnabledDownloadableSourcesAsReadinessGate(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := sources.NewManager(sources.Registry{Sources: []sources.Source{
		{ID: "list", Name: "List", Kind: "domains", URL: "https://example.com/list", Enabled: true},
		{ID: "disabled", Name: "Disabled", Kind: "cidrs", URL: "https://example.com/cidrs", Enabled: false},
		{ID: "docs", Name: "Docs", Kind: "reference", URL: "https://example.com/docs", Enabled: true},
	}}, filepath.Join(root, "sources"))
	a := &App{Store: store, Catalog: catalog.Catalog{}, Sources: manager, Start: time.Now()}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	a.status(response, request)
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["sources_total"] != float64(1) || result["sources_catalog_total"] != float64(3) || result["sources_downloadable"] != float64(2) || result["sources_reference"] != float64(1) {
		t.Fatalf("unexpected source counters: %v", result)
	}
}

func TestSourceDraftAPIIsIndependentAndVisibleInStatus(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := sources.NewManager(sources.Registry{Sources: []sources.Source{{
		ID: "list", Name: "List", Kind: "domains", URL: "https://example.com/list", Enabled: true,
	}}}, filepath.Join(root, "cache"), filepath.Join(root, "source-state.json"))
	a := &App{Store: store, Catalog: catalog.Catalog{}, Sources: manager, Start: time.Now()}

	draftRequest := httptest.NewRequest(http.MethodPost, "/api/v1/sources/list/draft", strings.NewReader(`{"enabled":false}`))
	draftResponse := httptest.NewRecorder()
	a.sourceAction(draftResponse, draftRequest)
	if draftResponse.Code != http.StatusOK || !manager.Dirty() {
		t.Fatalf("source draft failed: status=%d body=%s", draftResponse.Code, draftResponse.Body.String())
	}

	statusResponse := httptest.NewRecorder()
	a.status(statusResponse, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var status map[string]any
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status["sources_pending_changes"] != true || status["pending_changes"] != true || status["routing_pending_changes"] != false {
		t.Fatalf("source draft was not independently reported: %v", status)
	}
	if status["sources_total"] != float64(1) {
		t.Fatalf("draft changed active source readiness before apply: %v", status)
	}

	applyResponse := httptest.NewRecorder()
	a.sourceApply(applyResponse, httptest.NewRequest(http.MethodPost, "/api/v1/sources/apply", strings.NewReader(`{}`)))
	if applyResponse.Code != http.StatusOK || manager.Dirty() {
		t.Fatalf("source apply failed: status=%d body=%s", applyResponse.Code, applyResponse.Body.String())
	}
	states := manager.List()
	if len(states) != 1 || states[0].AppliedEnabled {
		t.Fatalf("source selection was not applied: %+v", states)
	}
}

func TestGlobalApplyRefusesToPretendItAppliedSourceDraft(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := sources.NewManager(sources.Registry{Sources: []sources.Source{{
		ID: "list", Name: "List", Kind: "domains", URL: "https://example.com/list", Enabled: true,
	}}}, filepath.Join(root, "cache"))
	if err := manager.SetDraft("list", false); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{}, Sources: manager, Start: time.Now()}
	response := httptest.NewRecorder()
	a.apply(response, httptest.NewRequest(http.MethodPost, "/api/v1/apply", strings.NewReader(`{}`)))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "CONTEXTUAL_APPLY_REQUIRED") || !manager.Dirty() {
		t.Fatalf("global apply silently consumed or misreported a source draft: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGlobalDiscardPreservesIndependentSourceDraft(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := sources.NewManager(sources.Registry{Sources: []sources.Source{{
		ID: "list", Name: "List", Kind: "domains", URL: "https://example.com/list", Enabled: true,
	}}}, filepath.Join(root, "cache"))
	if err := manager.SetDraft("list", false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{}, Sources: manager, Start: time.Now()}
	response := httptest.NewRecorder()
	a.discard(response, httptest.NewRequest(http.MethodPost, "/api/v1/discard", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("global discard failed: status=%d body=%s", response.Code, response.Body.String())
	}
	if store.Dirty() {
		t.Fatal("global discard left the routing draft pending")
	}
	if !manager.Dirty() {
		t.Fatal("global discard unexpectedly removed the independent source draft")
	}
}

func TestPlanSummarizesIncludedAndDeferredScopes(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.25"}}); err != nil {
		t.Fatal(err)
	}
	manager := sources.NewManager(sources.Registry{Sources: []sources.Source{{
		ID: "list", Name: "List", Kind: "domains", URL: "https://example.com/list", Enabled: true,
	}}}, filepath.Join(root, "cache"))
	if err := manager.SetDraft("list", false); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}}}, Sources: manager, Start: time.Now()}
	response := httptest.NewRecorder()
	a.plan(response, httptest.NewRequest(http.MethodGet, "/api/v1/plan?scope=services", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("plan failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Summary applyChangeSummary `json:"change_summary"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Summary.Scope != changeScopeServices || len(payload.Summary.Services) != 1 || len(payload.Summary.Devices) != 0 || !payload.Summary.NetworkChange || payload.Summary.WorkingChange {
		t.Fatalf("unexpected included summary: %+v", payload.Summary)
	}
	deferred := map[string]int{}
	for _, item := range payload.Summary.Deferred {
		deferred[item.ID] = item.Count
	}
	if deferred["devices"] != 1 || deferred["sources"] != 1 {
		t.Fatalf("independent changes are missing from deferred summary: %+v", payload.Summary.Deferred)
	}
}

func TestPlanDoesNotTreatSwitchToDirectAsNetworkNoop(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.AppliedServices["telegram"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "direct"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}}}}
	plan, err := a.buildDataplanePlanForScope(cfg, []routecatalog.Option{{ID: "nfqws2", Installed: true, Selectable: true}}, changeScopeServices, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Noop || len(plan.RetiringAdapters) != 1 || plan.RetiringAdapters[0] != "nfqws2" {
		t.Fatalf("switch to direct lost previous runtime adapter: %+v", plan)
	}
}

func TestPlanKeepsAdapterUsedByAnotherDesiredService(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.AppliedServices["telegram"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	cfg.AppliedServices["youtube"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "direct"}
	cfg.Services["youtube"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}, {ID: "youtube", Name: "YouTube"}}}}
	plan, err := a.buildDataplanePlanForScope(cfg, []routecatalog.Option{{ID: "nfqws2", Installed: true, Selectable: true}}, changeScopeServices, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RetiringAdapters) != 0 {
		t.Fatalf("shared adapter was incorrectly retired: %+v", plan.RetiringAdapters)
	}
}

func TestStatusReportsDataplaneJournalFailureWithoutLeakingPath(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "private-dataplane-state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "latest-plan.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{}, Dataplane: dataplane.New(stateRoot), Start: time.Now()}
	response := httptest.NewRecorder()
	a.status(response, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["dataplane_state"] != "journal-error" || result["dataplane_error"] != "dataplane journal unavailable" {
		t.Fatalf("journal failure was not reported safely: %v", result)
	}
	if strings.Contains(response.Body.String(), stateRoot) {
		t.Fatalf("public status leaked private state path: %s", response.Body.String())
	}
}

func (r deviceRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.output), nil
}

func (confirmedRouteProber) Probe(_ context.Context, service catalog.Service, route string) testlab.Result {
	return testlab.Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL, Route: route, Status: "pass", LatencyMS: 12, CheckedAt: time.Now().UTC().Format(time.RFC3339), RouteConfirmed: true, EvidenceSource: "test-adapter"}
}

func TestAPIServiceAndHTTPSListRefresh(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a.example\nb.example\ncom\n"))
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := sources.Registry{Sources: []sources.Source{{ID: "test", Name: "Test", Kind: "domains", URL: upstream.URL, Enabled: true, MinEntries: 2, MaxBytes: 4096}}}
	sm := sources.NewManager(reg, filepath.Join(tmp, "cache"))
	sm.SetHTTPClient(upstream.Client())
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "chatgpt", Name: "ChatGPT", Category: "AI", Domains: []string{"chatgpt.com"}, Strategy: []string{"usque"}, ProbeURL: "https://chatgpt.com/"}}}
	a := &App{Store: store, Catalog: cat, Sources: sm, Start: time.Now(), EffectiveListen: "127.0.0.1:8787"}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/services/chatgpt", strings.NewReader(`{"enabled":true,"mode":"auto"}`))
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("toggle status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, err = http.Post(ts.URL+"/api/v1/sources/test/refresh", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d", resp.StatusCode)
	}
	var st sources.State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !st.Ready || st.Entries != 2 {
		t.Fatalf("unexpected source state: %+v", st)
	}

	resp, err = http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if status["listen"] != "127.0.0.1:8787" {
		t.Fatalf("effective listen not reported: %v", status["listen"])
	}
	if got := int(status["process_id"].(float64)); got != os.Getpid() {
		t.Fatalf("process_id=%d, want %d", got, os.Getpid())
	}
}

func TestCatalogSnapshotEnrichesOnlyExplicitServiceSources(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "sources")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "telegram.lst"), []byte("149.154.160.0/20\n91.108.56.0/22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := sources.NewManager(sources.Registry{Sources: []sources.Source{{
		ID: "telegram", Name: "Telegram networks", Kind: "cidrs", URL: "https://example.com/telegram", Enabled: true, Services: []string{"telegram"},
	}}}, cache)
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{
		{ID: "telegram", Name: "Telegram", Category: "Messaging", Domains: []string{"telegram.org"}, CIDRs: []string{"91.108.56.0/22"}, Strategy: []string{"usque"}},
		{ID: "youtube", Name: "YouTube", Category: "Video", Domains: []string{"youtube.com"}, Strategy: []string{"nfqws2"}},
	}}, Sources: manager}
	snapshot := a.catalogSnapshot()
	if got := strings.Join(snapshot.Services[0].CIDRs, ","); got != "149.154.160.0/20,91.108.56.0/22" {
		t.Fatalf("telegram CIDR enrichment failed: %s", got)
	}
	if len(snapshot.Services[1].CIDRs) != 0 {
		t.Fatalf("telegram source leaked into YouTube: %v", snapshot.Services[1].CIDRs)
	}
}

func TestSelectorsAndConnectionsAPI(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube", Category: "Video", Domains: []string{"youtube.com"}, Strategy: []string{"nfqws2"}}}}
	tele := telemetry.NewStore()
	tele.Upsert(telemetry.Connection{ID: "c1", ServiceID: "youtube", ServiceName: "YouTube", Host: "googlevideo.com", Protocol: "tcp", SourceIP: "192.168.1.10", Route: "nfqws2", Chain: []string{"YouTube", "NFQWS2"}, Upload: 10, Download: 20})
	a := &App{Store: store, Catalog: cat, Telemetry: tele, Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/services/youtube", strings.NewReader(`{"enabled":true,"route":"direct"}`))
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("selector status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatal(err)
	}
	var views []serviceView
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(views) != 1 || views[0].Route != "direct" || views[0].Planned != "direct" {
		t.Fatalf("unexpected selector view: %+v", views)
	}

	resp, err = http.Get(ts.URL + "/api/v1/connections")
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		Connections []telemetry.Connection `json:"connections"`
		Active      int                    `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cp); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if cp.Active != 1 || len(cp.Connections) != 1 || cp.Connections[0].Route != "nfqws2" {
		t.Fatalf("unexpected connections: %+v", cp)
	}
}

func TestUnavailableRouteCanBeDisabledButNotEnabled(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "missing-engine"}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}}}, Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatal(err)
	}
	var views []serviceView
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(views) != 1 || views[0].RouteAvailable || views[0].RouteIssue == "" {
		t.Fatalf("unavailable route was not explained: %+v", views)
	}

	put := func(body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/services/telegram", strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	disabled := put(`{"enabled":false,"route":"missing-engine"}`)
	if disabled.StatusCode != http.StatusOK {
		t.Fatalf("disable stale route status=%d body=%s", disabled.StatusCode, readTestBody(disabled))
	}
	_ = disabled.Body.Close()

	enabled := put(`{"enabled":true,"route":"missing-engine"}`)
	if enabled.StatusCode != http.StatusConflict {
		t.Fatalf("enable stale route status=%d body=%s", enabled.StatusCode, readTestBody(enabled))
	}
	var failure map[string]any
	if err := json.NewDecoder(enabled.Body).Decode(&failure); err != nil {
		t.Fatal(err)
	}
	_ = enabled.Body.Close()
	if failure["code"] != "ROUTE_UNAVAILABLE" || failure["resolution"] == "" {
		t.Fatalf("missing recovery action: %+v", failure)
	}
}

func TestDraftApplyDiscardAndSystemAPI(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube", Category: "Video", Domains: []string{"youtube.com"}, Strategy: []string{"nfqws2"}}}}
	a := &App{Store: store, Catalog: cat, Telemetry: telemetry.NewStore(), Start: time.Now(), EffectiveListen: "127.0.0.1:18789"}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	putService := func(body string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/services/youtube", strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT service status=%d", resp.StatusCode)
		}
	}
	getStatus := func() map[string]any {
		t.Helper()
		resp, err := http.Get(ts.URL + "/api/v1/status")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var got map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	post := func(path string) {
		t.Helper()
		resp, err := http.Post(ts.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s status=%d", path, resp.StatusCode)
		}
	}

	putService(`{"enabled":true,"route":"direct"}`)
	if pending, _ := getStatus()["pending_changes"].(bool); !pending {
		t.Fatal("expected pending_changes=true after draft edit")
	}

	post("/api/v1/apply")
	if pending, _ := getStatus()["pending_changes"].(bool); pending {
		t.Fatal("expected pending_changes=false after apply")
	}

	resp, err := http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatal(err)
	}
	var views []serviceView
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(views) != 1 || !views[0].Applied || views[0].AppliedRoute != "direct" || views[0].Dirty {
		t.Fatalf("unexpected applied service view: %+v", views)
	}

	putService(`{"enabled":false,"route":"auto"}`)
	if pending, _ := getStatus()["pending_changes"].(bool); !pending {
		t.Fatal("expected second edit to create pending changes")
	}
	post("/api/v1/discard")
	resp, err = http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatal(err)
	}
	views = nil
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(views) != 1 || !views[0].Enabled || views[0].Route != "direct" || views[0].Dirty {
		t.Fatalf("discard did not restore applied state: %+v", views)
	}

	resp, err = http.Get(ts.URL + "/api/v1/system")
	if err != nil {
		t.Fatal(err)
	}
	var sys map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&sys); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if sys["architecture"] == "" || sys["architecture"] == nil {
		t.Fatalf("system probe missing architecture: %+v", sys)
	}
}

func TestLiveApplyDoesNotAdvanceWhenDataplanePlanIsBlocked(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	cfg := config.Default()
	cfg.SafeMode = false
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	a := &App{
		Store:     store,
		Catalog:   catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube", Domains: []string{"youtube.com"}, Strategy: []string{"nfqws2"}}}},
		Dataplane: manager,
		Start:     time.Now(),
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	response, err := http.Post(server.URL+"/api/v1/apply", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.StatusCode, readTestBody(response))
	}
	if !store.Dirty() || store.Get().AppliedServices["youtube"].Enabled {
		t.Fatalf("blocked live apply advanced applied state: %+v", store.Get())
	}
	latest, exists, err := manager.Latest()
	if err != nil || !exists || latest.Ready || latest.State != "blocked" {
		t.Fatalf("unexpected transaction journal: exists=%v plan=%+v err=%v", exists, latest, err)
	}
	statusResponse, err := http.Get(server.URL + "/api/v1/dataplane/status")
	if err != nil {
		t.Fatal(err)
	}
	defer statusResponse.Body.Close()
	var status struct {
		Exists bool           `json:"exists"`
		Plan   dataplane.Plan `json:"plan"`
	}
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if statusResponse.StatusCode != http.StatusOK || !status.Exists || status.Plan.Digest != latest.Digest {
		t.Fatalf("unexpected dataplane status: code=%d status=%+v", statusResponse.StatusCode, status)
	}
}

func TestEngineConfigAPIStagesValidatesAndSafeModeBlocksApply(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := engineconfig.New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backups"))
	a := &App{Store: store, Catalog: catalog.Catalog{}, EngineConfigs: mgr, Telemetry: telemetry.NewStore(), Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/engine-configs/nfqws2/file?file=main", strings.NewReader(`{"content":"ISP_INTERFACE=\\\"eth3\\\"\nNFQWS_ARGS=\\\"--filter-tcp=443\\\"\n"}`))
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stage status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, err = http.Post(ts.URL+"/api/v1/engine-configs/nfqws2/validate?file=main", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate status=%d", resp.StatusCode)
	}
	var validation engineconfig.Validation
	if err := json.NewDecoder(resp.Body).Decode(&validation); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !validation.OK {
		t.Fatalf("validation failed: %+v", validation)
	}

	resp, err = http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := int(status["engine_config_drafts"].(float64)); got != 1 {
		t.Fatalf("draft count=%d", got)
	}

	resp, err = http.Post(ts.URL+"/api/v1/engine-configs/nfqws2/apply?file=main", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("Safe Mode apply status=%d", resp.StatusCode)
	}
}

func TestUnifiedApplyKeepsUnroutedEngineDraftPending(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	cfg := config.Default()
	cfg.SafeMode = false
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	mgr := engineconfig.New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backups"))
	a := &App{Store: store, Catalog: catalog.Catalog{}, EngineConfigs: mgr, Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/engine-configs/warp-wg/file?file=main", strings.NewReader(`{"content":"[Interface]\nPrivateKey = test\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = peer\nEndpoint = 1.1.1.1:2408\nAllowedIPs = 0.0.0.0/0\n"}`))
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stage status=%d", resp.StatusCode)
	}

	resp, err = http.Post(ts.URL+"/api/v1/apply", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("apply status=%d body=%s", resp.StatusCode, readTestBody(resp))
	}
	var payload struct {
		Pending     bool           `json:"pending_changes"`
		Transaction dataplane.Plan `json:"transaction"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Pending || len(payload.Transaction.Blockers) != 1 || payload.Transaction.Blockers[0].Code != "ENGINE_DRAFT_UNUSED" {
		t.Fatalf("unexpected apply response: %+v", payload)
	}

	resp, err = http.Post(ts.URL+"/api/v1/apply?scope=routing", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("routing apply status=%d body=%s", resp.StatusCode, readTestBody(resp))
	}
	var scoped struct {
		Pending      bool `json:"pending_changes"`
		ScopePending bool `json:"scope_pending_changes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&scoped); err != nil {
		t.Fatal(err)
	}
	if !scoped.Pending || scoped.ScopePending {
		t.Fatalf("routing scope did not isolate unrelated engine draft: %+v", scoped)
	}
	if got := mgr.List()[2].Files[0].Staged; !got {
		t.Fatal("routing apply unexpectedly discarded the unrelated WARP draft")
	}

	resp, err = http.Post(ts.URL+"/api/v1/discard", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discard status=%d", resp.StatusCode)
	}
	if got := mgr.List()[2].Files[0].Staged; got {
		t.Fatal("global discard left WARP draft staged")
	}
}

func TestServiceAndDevicePagesApplyOnlyTheirOwnFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.25"}}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", ProbeURL: "https://telegram.org/"}}}, Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	response, err := http.Post(ts.URL+"/api/v1/apply?scope=services", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("service apply status=%d body=%s", response.StatusCode, readTestBody(response))
	}
	applied := store.Get().AppliedServices["telegram"]
	if !applied.Enabled || applied.Route != "direct" || len(applied.Sources) != 0 {
		t.Fatalf("service page leaked device fields: %+v", applied)
	}
	if store.DirtyScope(config.DraftScopeServices) || !store.DirtyScope(config.DraftScopeDevices) {
		t.Fatal("device policy did not remain independently pending")
	}

	response, err = http.Post(ts.URL+"/api/v1/apply?scope=devices", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device apply status=%d body=%s", response.StatusCode, readTestBody(response))
	}
	applied = store.Get().AppliedServices["telegram"]
	if len(applied.Sources) != 1 || applied.Sources[0] != "192.168.1.25/32" || store.Dirty() {
		t.Fatalf("device page did not commit only its source policy: %+v", applied)
	}
}

func TestConfigForChangeScopeUsesOnlyPageOwnedDraft(t *testing.T) {
	cfg := config.Default()
	cfg.Services["telegram"] = config.ServiceState{Enabled: true, Route: "sing-box", Mode: "sing-box", Sources: []string{"192.168.1.25/32"}}
	cfg.AppliedServices["telegram"] = config.ServiceState{Enabled: true, Route: "direct", Mode: "direct"}

	services := configForChangeScope(cfg, changeScopeServices).Services["telegram"]
	if services.Route != "sing-box" || len(services.Sources) != 0 {
		t.Fatalf("service scope=%+v", services)
	}
	devices := configForChangeScope(cfg, changeScopeDevices).Services["telegram"]
	if devices.Route != "direct" || len(devices.Sources) != 1 {
		t.Fatalf("device scope=%+v", devices)
	}
	engine := configForChangeScope(cfg, changeScopeEngine).Services["telegram"]
	if engine.Route != "direct" || len(engine.Sources) != 0 {
		t.Fatalf("engine scope=%+v", engine)
	}
}

func TestValidStagedWARPProfileCanBeSelectedBeforeFirstApply(t *testing.T) {
	tmp := t.TempDir()
	configs := engineconfig.New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backups"))
	profile := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`
	if _, err := configs.Stage("warp-wg", "main", profile); err != nil {
		t.Fatal(err)
	}
	a := &App{EngineConfigs: configs}
	if !a.validStagedWARPProfile() {
		t.Fatal("valid staged WARP profile was not recognized")
	}
	options := []routecatalog.Option{{ID: "warp-wg", Installed: true}}
	if options[0].Selectable {
		t.Fatal("test precondition: WARP option is already selectable")
	}
	if options[0].Ready {
		t.Fatal("test precondition: WARP option is already ready")
	}
	a.prepareRouteOption(&options[0])
	if !options[0].Selectable {
		t.Fatal("valid staged WARP option remains unselectable")
	}
	if options[0].Ready {
		t.Fatal("untested staged WARP option was exposed to AUTO")
	}
	if !routecatalog.ValidWithOptions("warp-wg", options) {
		t.Fatal("staged WARP route cannot be selected for its first transactional Apply")
	}
}

func TestInvalidStagedWARPProfileRemainsUnavailable(t *testing.T) {
	tmp := t.TempDir()
	configs := engineconfig.New(filepath.Join(tmp, "stage"), filepath.Join(tmp, "backups"))
	if _, err := configs.Stage("warp-wg", "main", "[Interface]\nPrivateKey = invalid\n"); err != nil {
		t.Fatal(err)
	}
	a := &App{EngineConfigs: configs}
	option := routecatalog.Option{ID: "warp-wg", Installed: true}
	a.prepareRouteOption(&option)
	if a.validStagedWARPProfile() || option.Selectable {
		t.Fatal("invalid staged WARP profile was accepted")
	}
}

func TestTestLabAPIUsesFixedCatalogProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := testlab.NewRunner()
	runner.Client = upstream.Client()
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "probe", Name: "Probe Service", Category: "Test", ProbeURL: upstream.URL}}}
	a := &App{Store: store, Catalog: cat, TestLab: runner, Telemetry: telemetry.NewStore(), Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/testlab/current", "application/json", strings.NewReader(`{"services":["probe"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("testlab run status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp, err = http.Get(ts.URL + "/api/v1/testlab")
	if err != nil {
		t.Fatal(err)
	}
	var snap testlab.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(snap.Current) != 1 || snap.Current[0].Status != "pass" {
		t.Fatalf("unexpected testlab snapshot: %+v", snap)
	}
}

func TestServiceEvidenceNeverUsesDesiredOrPlannedRoute(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("probe", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "probe", Name: "Probe"}}}, TestLab: testlab.NewRunner()}
	views := a.serviceEvidenceSnapshot(store.Get(), a.Catalog.Services)
	if got := views["probe"].Level; got != evidence.Catalog {
		t.Fatalf("desired route promoted evidence to %s", got)
	}
}

func TestServiceEvidenceRequiresMatchingAppliedRouteProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("probe", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	runner := testlab.NewRunner()
	runner.Client = upstream.Client()
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "probe", Name: "Probe", ProbeURL: upstream.URL}}}
	a := &App{Store: store, Catalog: cat, TestLab: runner}
	runner.ProbeCurrent(context.Background(), cat, []string{"probe"})
	views := a.serviceEvidenceSnapshot(store.Get(), cat.Services)
	if got := views["probe"].Level; got != evidence.Runtime {
		t.Fatalf("current-path probe level=%s, want runtime", got)
	}
	runner.ProbeRoutes(context.Background(), cat, []string{"probe"}, []string{"nfqws2"}, confirmedRouteProber{})
	views = a.serviceEvidenceSnapshot(store.Get(), cat.Services)
	if got := views["probe"].Level; got != evidence.Runtime {
		t.Fatalf("probe for non-applied route promoted evidence to %s", got)
	}
	runner.ProbeRoutes(context.Background(), cat, []string{"probe"}, []string{"direct"}, confirmedRouteProber{})
	views = a.serviceEvidenceSnapshot(store.Get(), cat.Services)
	if got := views["probe"].Level; got != evidence.Service {
		t.Fatalf("matching isolated probe level=%s, want service-confirmed", got)
	}
}

func TestPlanReusesEvidenceOnlyFromMatchingCommittedTransaction(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("probe", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "probe", Name: "Probe", ProbeURL: "https://example.com/"}}}
	a := &App{Store: store, Catalog: cat, Dataplane: manager}
	committed, err := a.buildDataplanePlan(store.Get(), a.routeOptionsSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	committed.State = "committed"
	committed.ObservedEvidence = evidence.Service
	committed.EvidenceNote = "confirmed evidence"
	committed.RouteEvidence[0].Observed = evidence.Service
	committed.RouteEvidence[0].Source = "isolated-test"
	if err := manager.Record(committed); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	a.plan(response, httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("plan status=%d body=%s", response.Code, response.Body.String())
	}
	var matching struct {
		Transaction dataplane.Plan `json:"transaction"`
	}
	if err := json.NewDecoder(response.Body).Decode(&matching); err != nil {
		t.Fatal(err)
	}
	if matching.Transaction.State != "committed" || matching.Transaction.ObservedEvidence != evidence.Service || matching.Transaction.RouteEvidence[0].Source != "isolated-test" {
		t.Fatalf("matching committed evidence was not restored: %+v", matching.Transaction)
	}

	if err := store.UpdateService("probe", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	a.plan(response, httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil))
	var changed struct {
		Transaction dataplane.Plan `json:"transaction"`
	}
	if err := json.NewDecoder(response.Body).Decode(&changed); err != nil {
		t.Fatal(err)
	}
	if changed.Transaction.State == "committed" || changed.Transaction.ObservedEvidence != evidence.None {
		t.Fatalf("changed draft inherited old evidence: %+v", changed.Transaction)
	}
}

func TestIsolatedRouteAPIAddsDirectControlAndFeedsSmartRoute(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	smart, err := smartroute.New("")
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "probe", Name: "Probe", ProbeURL: "https://example.com/", Strategy: []string{"direct"}}}}
	a := &App{Store: store, Catalog: cat, TestLab: testlab.NewRunner(), RouteProber: confirmedRouteProber{}, SmartRoute: smart, Start: time.Now()}
	ts := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/api/v1/testlab/routes", "application/json", strings.NewReader(`{"services":["probe"],"routes":["nfqws2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var payload struct {
		ControlAdded bool                           `json:"control_added"`
		Results      []testlab.Result               `json:"results"`
		Assessments  []testlab.ComparisonAssessment `json:"assessments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.ControlAdded || len(payload.Results) != 2 || len(payload.Assessments) != 1 || payload.Assessments[0].Conclusion != "direct-sufficient" {
		t.Fatalf("DIRECT control was not added: %+v", payload)
	}
	if got := smart.Suggest("probe", "fallback"); got != "direct" {
		t.Fatalf("suggestion=%q", got)
	}
}

func TestAppSecurityGateProtectsMutation(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdefghijklmnopqrstuvwxyz-ADMIN"
	gate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{
		Store:    store,
		Catalog:  catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube"}}},
		Security: gate,
		Start:    time.Now(),
	}
	handler := a.Handler(http.NotFoundHandler())

	unauthorized := httptest.NewRequest(http.MethodPut, "http://router.local/api/v1/services/youtube", strings.NewReader(`{"enabled":true,"route":"direct"}`))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorized.Header.Set("Origin", "http://router.local")
	unauthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResult, unauthorized)
	if unauthorizedResult.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d, want %d", unauthorizedResult.Code, http.StatusUnauthorized)
	}
	if _, exists := store.Get().Services["youtube"]; exists {
		t.Fatal("unauthorized mutation changed the store")
	}

	authorized := httptest.NewRequest(http.MethodPut, "http://router.local/api/v1/services/youtube", strings.NewReader(`{"enabled":true,"route":"direct"}`))
	authorized.Header.Set("Content-Type", "application/json")
	authorized.Header.Set("Origin", "http://router.local")
	authorized.Header.Set("Authorization", "Bearer "+token)
	authorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResult, authorized)
	if authorizedResult.Code != http.StatusOK {
		t.Fatalf("authorized status=%d, body=%s", authorizedResult.Code, authorizedResult.Body.String())
	}
	if !store.Get().Services["youtube"].Enabled {
		t.Fatal("authorized mutation was not persisted")
	}
}

func TestMutationAuditRecordsOutcomeWithoutRequestBody(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.Load(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal := auditlog.New(filepath.Join(tmp, "audit", "events.jsonl"))
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}}}, Audit: journal, Start: time.Now()}
	handler := a.Handler(http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodPut, "http://router.local/api/v1/services/telegram", strings.NewReader(`{"enabled":true,"route":"direct","password":"must-not-be-logged"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://router.local")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	snapshot := journal.Read(10)
	if len(snapshot.Events) != 1 || snapshot.Events[0].Path != "/api/v1/services/telegram" || snapshot.Events[0].Outcome != "ok" {
		t.Fatalf("events = %+v", snapshot.Events)
	}
	raw, err := os.ReadFile(journal.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "must-not-be-logged") || strings.Contains(string(raw), "password") {
		t.Fatalf("audit leaked request body: %s", raw)
	}
}

func TestPlannedEngineSkipsUnavailableRoutes(t *testing.T) {
	options := []routecatalog.Option{
		{ID: "auto", Selectable: true, Ready: true},
		{ID: "direct", Selectable: true, Ready: true},
		{ID: "nfqws2", Selectable: false},
		{ID: "sing-box", Selectable: true, Ready: true},
		{ID: "usque", Selectable: true, Ready: true},
	}
	service := catalog.Service{Strategy: []string{"nfqws2", "sing-box:ai-primary"}}
	if got := plannedEngineWithOptions(service, []string{"usque"}, options); got != "usque" {
		t.Fatalf("strategy fallback=%q", got)
	}
	service.Strategy = nil
	if got := plannedEngineWithOptions(service, []string{"xray", "usque"}, options); got != "usque" {
		t.Fatalf("order fallback=%q", got)
	}
	if got := plannedEngineWithOptions(service, []string{"xray"}, options); got != "direct" {
		t.Fatalf("direct fallback=%q", got)
	}
}

func TestPortableProfileExportPreviewAndDraftImport(t *testing.T) {
	makeApp := func(root string) *App {
		store, err := config.Load(filepath.Join(root, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		custom, err := customservices.Load(filepath.Join(root, "custom.json"))
		if err != nil {
			t.Fatal(err)
		}
		return &App{
			Store:          store,
			Catalog:        catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube", Category: "Video", Domains: []string{"youtube.com"}, Strategy: []string{"auto"}}}},
			CustomServices: custom,
			EngineConfigs:  engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups")),
			Start:          time.Now(),
		}
	}

	source := makeApp(filepath.Join(t.TempDir(), "source"))
	if err := source.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CustomServices.Create(catalog.Service{ID: "example", Name: "Example", Category: "Custom", Domains: []string{"example.com"}, Strategy: []string{"auto"}}, source.reservedServiceIDs()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.EngineConfigs.Stage("nfqws2", "user-list", "youtube.com\n"); err != nil {
		t.Fatal(err)
	}
	sourceServer := httptest.NewServer(source.Handler(http.NotFoundHandler()))
	defer sourceServer.Close()
	response, err := http.Get(sourceServer.URL + "/api/v1/profiles/export?name=Home")
	if err != nil {
		t.Fatal(err)
	}
	var bundle profileexchange.Bundle
	if err := json.NewDecoder(response.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || bundle.ContainsSecrets || len(bundle.EngineFiles) != 1 {
		t.Fatalf("export status=%d bundle=%+v", response.StatusCode, bundle)
	}
	if err := profileexchange.Validate(bundle); err != nil {
		t.Fatal(err)
	}

	target := makeApp(filepath.Join(t.TempDir(), "target"))
	targetServer := httptest.NewServer(target.Handler(http.NotFoundHandler()))
	defer targetServer.Close()
	encoded, _ := json.Marshal(bundle)
	previewResponse, err := http.Post(targetServer.URL+"/api/v1/profiles/preview", "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if previewResponse.StatusCode != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", previewResponse.StatusCode, readTestBody(previewResponse))
	}
	_ = previewResponse.Body.Close()
	requestBody, _ := json.Marshal(map[string]any{"bundle": bundle, "allow_custom_updates": false})
	importResponse, err := http.Post(targetServer.URL+"/api/v1/profiles/import", "application/json", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	if importResponse.StatusCode != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.StatusCode, readTestBody(importResponse))
	}
	_ = importResponse.Body.Close()
	if state := target.Store.Get().Services["youtube"]; !state.Enabled || state.Route != "auto" {
		t.Fatalf("service was not staged: %+v", state)
	}
	if !target.CustomServices.Has("custom-example") {
		t.Fatal("custom service was not imported")
	}
	content, err := target.EngineConfigs.Read("nfqws2", "user-list")
	if err != nil || content.Source != "staged" || content.Content != "youtube.com\n" {
		t.Fatalf("engine draft=%+v err=%v", content, err)
	}
}

func TestEncryptedPrivateBackupRestoresSensitiveConfigIntoDraftOnly(t *testing.T) {
	makeApp := func(root string) *App {
		store, err := config.Load(filepath.Join(root, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		custom, err := customservices.Load(filepath.Join(root, "custom.json"))
		if err != nil {
			t.Fatal(err)
		}
		deviceManager, err := devices.Load(filepath.Join(root, "devices.json"))
		if err != nil {
			t.Fatal(err)
		}
		return &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube"}}}, CustomServices: custom, Devices: deviceManager, EngineConfigs: engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups")), Start: time.Now()}
	}

	source := makeApp(filepath.Join(t.TempDir(), "source"))
	if err := source.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "warp-wg"}); err != nil {
		t.Fatal(err)
	}
	secret := "[Interface]\nPrivateKey = very-secret-private-key\n"
	if _, err := source.EngineConfigs.Stage("warp-wg", "main", secret); err != nil {
		t.Fatal(err)
	}
	exportBody, _ := json.Marshal(map[string]string{"password": "correct horse battery staple"})
	exportRequest := httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/export", bytes.NewReader(exportBody))
	exportRequest.Header.Set("Content-Type", "application/json")
	exportResponse := httptest.NewRecorder()
	source.Handler(http.NotFoundHandler()).ServeHTTP(exportResponse, exportRequest)
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	var envelope privatebackup.Envelope
	if err := json.Unmarshal(exportResponse.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || len(payload.EngineFiles) != 1 || !payload.EngineFiles[0].Sensitive || payload.EngineFiles[0].Content != secret {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}

	target := makeApp(filepath.Join(t.TempDir(), "target"))
	importBody, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple", "confirm": "IMPORT_PRIVATE_BACKUP"})
	importRequest := httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/import", bytes.NewReader(importBody))
	importRequest.Header.Set("Content-Type", "application/json")
	importResponse := httptest.NewRecorder()
	target.Handler(http.NotFoundHandler()).ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}
	restored, err := target.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil || restored.Source != "staged" || restored.Content != secret {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
	if target.Store.Get().AppliedServices["youtube"].Enabled {
		t.Fatal("private backup changed live/applied services")
	}
}

func readTestBody(response *http.Response) string {
	data := make([]byte, 4096)
	n, _ := response.Body.Read(data)
	_ = response.Body.Close()
	return string(data[:n])
}

func TestDomainDiagnosticExplainsCatalogConflicts(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.Catalog{Services: []catalog.Service{
		{ID: "youtube", Name: "YouTube", Category: "Video", Domains: []string{"youtube.com"}, Strategy: []string{"nfqws2"}},
		{ID: "google-video", Name: "Google Video", Category: "Video", Domains: []string{"www.youtube.com"}, Strategy: []string{"direct"}},
	}}
	a := &App{Store: store, Catalog: cat, Start: time.Now()}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	response, err := http.Get(server.URL + "/api/v1/diagnostics/domain?q=https%3A%2F%2Fwww.youtube.com%2Fwatch")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		Normalized      string           `json:"normalized"`
		Conflict        bool             `json:"conflict"`
		Matches         []map[string]any `json:"matches"`
		WinnerCandidate map[string]any   `json:"winner_candidate"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result.Normalized != "www.youtube.com" || !result.Conflict || len(result.Matches) != 2 {
		t.Fatalf("unexpected diagnostic: %+v", result)
	}
	if result.WinnerCandidate["matched_rule"] != "www.youtube.com" {
		t.Fatalf("specific match did not win: %+v", result.WinnerCandidate)
	}
}

func TestDiagnosticReportIsPrivacySafe(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("private-client", config.ServiceState{
		Enabled: true,
		Route:   "direct",
		Sources: []string{"192.168.1.25", "192.168.1.0/24"},
	}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Start: time.Now()}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics/report", nil)
	response := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, "192.168.1.25") || strings.Contains(body, "192.168.1.0/24") {
		t.Fatalf("diagnostic leaked client scope: %s", body)
	}
	var document diagnosticDocument
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	if document.Kind != "razvilka-diagnostic" || document.Schema != 2 {
		t.Fatalf("unexpected document identity: %+v", document)
	}
	if document.System.Hostname != "" {
		t.Fatalf("diagnostic leaked hostname %q", document.System.Hostname)
	}
	if len(document.Digest) != 64 || len(document.PrivacyOmissions) == 0 {
		t.Fatalf("missing integrity/privacy metadata: %+v", document)
	}
}

func TestDeviceAPIReportsScopedPoliciesAndStoresFriendlyName(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.25"}}); err != nil {
		t.Fatal(err)
	}
	deviceManager, err := devices.Load(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	deviceManager.IPCommand = "ip"
	deviceManager.Runner = deviceRunner{output: "192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"}
	deviceManager.ARPPaths, deviceManager.LeasePaths = nil, nil
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "youtube", Name: "YouTube"}}}, Devices: deviceManager, Start: time.Now()}
	handler := a.Handler(http.NotFoundHandler())

	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var views []deviceView
	if err := json.Unmarshal(listResponse.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || len(views[0].Policies) != 1 || views[0].Policies[0].Scope != "selected-device" {
		t.Fatalf("unexpected device views: %+v", views)
	}

	updateResponse := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/v1/devices/"+views[0].ID, strings.NewReader(`{"name":"TV","group":"Media"}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(updateResponse, request)
	if updateResponse.Code != http.StatusOK || !strings.Contains(updateResponse.Body.String(), `"name":"TV"`) {
		t.Fatalf("update status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
}

func TestZ2KIsNotAnInstallableComponent(t *testing.T) {
	a := &App{Components: &components.Manager{}, Start: time.Now()}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/components/z2k/plan?action=remove", nil)
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestComponentRemovalFindsDesiredAndAppliedDependencies(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("discord", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("chatgpt", config.ServiceState{Enabled: true, Route: "sing-box:ai-primary"}); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store}
	desired, applied := a.componentServiceReferences("nfqws2")
	if len(desired) != 1 || desired[0] != "discord" || len(applied) != 0 {
		t.Fatalf("unexpected nfqws2 references: desired=%v applied=%v", desired, applied)
	}
	desired, _ = a.componentServiceReferences("sing-box")
	if len(desired) != 1 || desired[0] != "chatgpt" {
		t.Fatalf("profile route was not matched: %v", desired)
	}
}
