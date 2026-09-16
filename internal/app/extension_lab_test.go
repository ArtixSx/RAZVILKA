package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

const ext5Key = "123e4567-e89b-12d3-a456-426614174000"

func ext5Request() map[string]any {
	return map[string]any{"content": "vless://" + ext5Key + "@edge.example:443?security=tls&sni=edge.example&type=tcp", "options": map[string]any{"index": 0, "socks_port": 18090}, "action": "preview", "confirm": "BUILD_MIHOMO_CONFIG"}
}
func TestExtensionMihomoRealHTTPAuthPreviewExportNoMutations(t *testing.T) {
	a, _ := awgAPITest(t)
	var canceled atomic.Int32
	a.reconciler.started = true
	a.reconciler.cancel = func() { canceled.Add(1) }
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	before := a.Store.Get()
	send := func(body any, auth bool) (int, []byte) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/extension-lab/mihomo", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if auth {
			req.Header.Set("Authorization", "Bearer "+awgAPIToken)
		}
		r, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode == 200 && !strings.Contains(r.Header.Get("Cache-Control"), "no-store") {
			t.Fatal("cached secret response")
		}
		return r.StatusCode, b
	}
	q := ext5Request()
	if code, _ := send(q, false); code != 401 {
		t.Fatal(code)
	}
	code, raw := send(q, true)
	if code != 200 || bytes.Contains(raw, []byte(ext5Key)) {
		t.Fatal(code, string(raw))
	}
	var v struct {
		Review string `json:"review"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v.Review) != 64 {
		t.Fatal(string(raw))
	}
	q["action"] = "export"
	q["review"] = strings.Repeat("0", 64)
	if code, _ = send(q, true); code != 409 {
		t.Fatal(code)
	}
	q["review"] = v.Review
	code, raw = send(q, true)
	if code != 200 || !bytes.Contains(raw, []byte(ext5Key)) {
		t.Fatal(code, string(raw))
	}
	if canceled.Load() != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("passive conversion altered automation/config")
	}
}
func TestExtensionPackHTTPImportsOnlyReviewedCandidates(t *testing.T) {
	a, send := awgAPITest(t)
	path := filepath.Join(t.TempDir(), "strategies.json")
	var e error
	a.StrategyLab, e = strategylab.New(path)
	if e != nil {
		t.Fatal(e)
	}
	before := a.Store.Get()
	w := send("GET", "/api/v1/strategy-lab/builtin-pack", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var builtin struct {
		Content string `json:"content"`
	}
	json.Unmarshal(w.Body.Bytes(), &builtin)
	q := map[string]any{"content": builtin.Content, "action": "preview", "signed": false}
	w = send("POST", "/api/v1/strategy-lab/packs", q)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var review strategylab.PackReview
	json.Unmarshal(w.Body.Bytes(), &review)
	q["action"] = "import"
	q["confirm"] = "IMPORT_STRATEGY_CANDIDATES"
	q["review"] = "wrong"
	if w = send("POST", "/api/v1/strategy-lab/packs", q); w.Code != 409 {
		t.Fatal(w.Code)
	}
	q["review"] = review.SHA256
	if w = send("POST", "/api/v1/strategy-lab/packs", q); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("import applied router config")
	}
	again, e := strategylab.New(path)
	if e != nil || len(again.Snapshot().Candidates) != 2 {
		t.Fatal(e)
	}
	for _, c := range again.Snapshot().Candidates {
		if c.Validation.Native || c.Validation.OK {
			t.Fatal("import manufactured native proof")
		}
	}
	q = map[string]any{"action": "export", "candidate_ids": []string{again.Snapshot().Candidates[0].ID}, "confirm": "EXPORT_STRATEGIES"}
	if w = send("POST", "/api/v1/strategy-lab/packs", q); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestExtensionHEVRejectsForeignAndUnsupportedSettings(t *testing.T) {
	a, send := awgAPITest(t)
	before := a.Store.Get()
	o := map[string]any{"interface": "rz-hev", "address": "172.31.21.1/30", "socks_port": 18081, "mtu": 1400, "max_sessions": 128}
	q := map[string]any{"options": o, "confirm": "BUILD_HEV_CONFIG"}
	w := send("POST", "/api/v1/extension-lab/hev", q)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"live_applied":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	o["interface"] = "eth0"
	if w = send("POST", "/api/v1/extension-lab/hev", q); w.Code != 400 {
		t.Fatal(w.Code)
	}
	o["interface"] = "rz-hev"
	o["post-up-script"] = "bad.sh"
	if w = send("POST", "/api/v1/extension-lab/hev", q); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("unexpected write")
	}
}
func TestExtensionCanceledAndCrossOriginRequestsDoNotExport(t *testing.T) {
	a, _ := awgAPITest(t)
	raw, _ := json.Marshal(ext5Request())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/api/v1/extension-lab/mihomo", bytes.NewReader(raw)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+awgAPIToken)
	w := httptest.NewRecorder()
	a.extensionMihomo(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "http://router.test/api/v1/extension-lab/mihomo", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+awgAPIToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://foreign.example")
	w = httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("cross origin accepted")
	}
}
