package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/telemetry"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

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

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/services/youtube", strings.NewReader(`{"enabled":true,"route":"nfqws2"}`))
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
	if len(views) != 1 || views[0].Route != "nfqws2" || views[0].Planned != "nfqws2" {
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
