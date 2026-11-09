//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Uses the real HTTP handler, original configured component owner, real
// installed binary/receipt and COMMON writers, VLESS peer, verified TLS and
// joined native cleanup. Only WAN label/platform classification is modeled;
// all public-format IPs exist solely inside disposable network namespaces.
func TestMihomoOriginalNativeHTTPServiceAndCleanup(t *testing.T) {
	runMihomoOriginalNativeHTTP(t, false)
}

func TestMihomoOriginalNativeHTTPReader4Fallback(t *testing.T) {
	if os.Getenv("RAZVILKA_EXECUTION_READER4_BINARY") == "" {
		t.Skip("actual pinned reader4 controller required")
	}
	runMihomoOriginalNativeHTTP(t, true)
}

func runMihomoOriginalNativeHTTP(t *testing.T, legacy bool) {
	if os.Getenv("RAZVILKA_MIHOMO_SERVICE_NATIVE") != "1" {
		t.Skip("isolated native fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	peers := domainOriginalPeers(t, ctx)
	archive, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	service := domainOriginalNativeService()
	service.Probes[0].Expect.BodyContains = append(service.Probes[0].Expect.BodyContains, `"Source":"1.1.1.2"`)
	service.Probes = append(service.Probes, catalog.Probe{ID: "second", Label: "Required actual TLS request", URL: "https://unknown.example.com/", Required: true, Expect: catalog.ProbeExpectation{BodyContains: []string{"native-domain-service"}}})
	service.Domains = append(service.Domains, "unknown.example.com")
	cfg := config.Default()
	cfg.SafeMode = false
	configPath := filepath.Join(peers.root, "http-config.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	cm := components.New()
	cm.Client = &http.Client{Transport: mihomoServiceArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			return nil, errors.New("unreviewed archive source")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
	})}
	m := dataplane.New(filepath.Join(installpath.State, "dataplane"))
	profile := func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }
	m.FreshProfile = profile
	a := &App{Store: store, Catalog: catalog.Catalog{Services: []catalog.Service{service}}, Components: cm, Dataplane: m, FreshProfile: profile,
		ComponentHistory: updatecheck.NewComponentHistoryAdmission(components.MihomoReleaseReadVersion), ExecutionHistory: updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion),
		SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: filepath.Join(peers.root, "http-control"), Directory: filepath.Join(peers.root, "http-update-files")}}
	// The production gate installs its immutable guard before the first
	// admitted operation, including creation of the actual control record.
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	held, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = operationgate.InitializeSelfUpdateControl(held, a.SelfUpdateFiles.ControlRoot)
	release()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := a.installMihomo(ctx); err != nil || !result.OK {
		t.Fatal("real installed component", result, err)
	}
	if err := a.ConfigureMihomoProbe(netidentity.NewProcProvider()); err != nil {
		t.Fatal(err)
	}
	var oldBytes []byte
	if legacy {
		oldBytes, err = os.ReadFile(os.Getenv("RAZVILKA_EXECUTION_READER4_BINARY"))
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(installpath.State, "update-backups", "reader4-pinned-d36")
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "razvilka.bin"), oldBytes, 0500); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(oldBytes)
		if err := os.WriteFile(filepath.Join(root, "razvilka.sha256"), []byte(hex.EncodeToString(hash[:])), 0600); err != nil {
			t.Fatal(err)
		}
		if a.ExecutionHistory.CheckWrite(ctx, 5) == nil {
			t.Fatal("actual retained reader4 admitted writer5")
		}
		if err := a.ExecutionHistory.CheckWrite(ctx, 4); err != nil {
			t.Fatal("actual retained reader4 denied legacy format", err)
		}
	}
	const token = "mihomo-real-http-native-token-1234567890"
	a.Security, err = security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	send := func(body any, auth bool, origin string) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		request, err := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v1/extension-lab/mihomo", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if auth {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	q := map[string]any{"content": fmt.Sprintf("vless://%s@%s:10443?security=tls&sni=front.example", domainOriginalUUID, domainOriginalServer), "options": map[string]any{"index": 0, "socks_port": 29430}, "action": "preview", "confirm": "BUILD_MIHOMO_CONFIG"}
	if code, _ := send(q, false, server.URL); code != 401 {
		t.Fatal("authentication", code)
	}
	if code, _ := send(q, true, "https://foreign.invalid"); code != 403 {
		t.Fatal("origin", code)
	}
	code, data := send(q, true, server.URL)
	if code != 200 {
		t.Fatal("real preview", code, string(data))
	}
	var preview struct {
		Review string `json:"review"`
	}
	if json.Unmarshal(data, &preview) != nil || len(preview.Review) != 64 {
		t.Fatal(string(data))
	}
	q["action"], q["confirm"], q["review"] = "probe", "PROBE_MIHOMO_SERVICE", preview.Review
	q["service_id"], q["expected_revision"] = service.ID, store.Get().Revision
	before := store.Get()
	started := time.Now()
	code, data = send(q, true, server.URL)
	var response struct {
		Probe  dataplane.MihomoServiceProbe `json:"probe"`
		Live   bool                         `json:"live_applied"`
		Timing *mihomoProbeAttemptTiming    `json:"timing"`
	}
	if code != 200 || json.Unmarshal(data, &response) != nil || !response.Probe.ServiceVerified || !response.Probe.CleanupVerified || response.Probe.ReviewSHA256 != preview.Review || response.Live || response.Probe.LiveApplied {
		t.Fatal("actual HTTP native service", code, string(data))
	}
	if response.Timing == nil || response.Timing.AdapterCheckMS == nil || response.Timing.PostcheckMS == nil || response.Timing.FinalizeMS == nil || response.Timing.HandlerElapsedMS < response.Probe.DurationMS || *response.Timing.AdapterCheckMS < response.Probe.DurationMS {
		t.Fatal("actual HTTP timings omitted source review, adapter or finalization", string(data))
	}
	timingJSON, err := json.Marshal(response.Timing)
	if err != nil {
		t.Fatal("encode bounded native timing", err)
	}
	t.Logf("mihomo_handler_timing=%s", timingJSON)
	if !reflect.DeepEqual(before, store.Get()) {
		t.Fatal("temporary service check changed config")
	}
	a.mihomoProbe.mu.Lock()
	pending := a.mihomoProbe.held != nil
	a.mihomoProbe.mu.Unlock()
	if pending || m.CheckExecutionRecovery(ctx) != nil {
		t.Fatal("HTTP result preceded original cleanup")
	}
	execution, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record dataplane.Execution
	if json.Unmarshal(execution, &record) != nil || record.State != "temporary-complete" || len(record.Resources) != 1 || record.Resources[0].Kind != "mihomo-probe" || record.Resources[0].Phase != "removed" {
		t.Fatal("actual COMMON terminal missing")
	}
	if legacy {
		if !record.Resources[0].MihomoProbe.Source.ParentOrigin.IsZero() || bytes.Contains(execution, []byte("parent_origin")) {
			t.Fatal("reader4 fallback published reader5 field")
		}
		if version, _, err := dataplane.InspectRetainedExecutionReadVersion(ctx, m.StateRoot); err != nil || version != 4 {
			t.Fatal("legacy history no longer readable", version, err)
		}
		after, err := os.ReadFile(filepath.Join(installpath.State, "update-backups", "reader4-pinned-d36", "razvilka.bin"))
		if err != nil || !bytes.Equal(oldBytes, after) {
			t.Fatal("fallback removed or changed retained controller", err)
		}
		t.Log("actual pinned d36 controller inventory refused5, separately admitted4; real HTTP service/cleanup passed with unchanged reader4 backup and omitted parent origin")
	}
	t.Logf("real HTTP preview→original installed source→native VLESS/TLS mandatory services→joined cleanup→HTTP response elapsed=%s result=%+v; no live route", time.Since(started), response.Probe)
}
