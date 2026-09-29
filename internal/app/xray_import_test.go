package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

const xrayImportURI = "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=reality&sni=front.example&fp=chrome&pbk=PUBLICKEY&sid=abcd&type=tcp&flow=xtls-rprx-vision#Home"

func TestXrayProfileImportStagesOnlyTheXrayDraft(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	a := &App{EngineConfigs: configs}
	const singBox = `{"outbounds":[{"type":"direct","tag":"original"}]}`
	if _, err := configs.Stage("sing-box", "main", singBox); err != nil {
		t.Fatal(err)
	}
	preview := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"profile": xrayImportURI, "engine": "xray"})
	a.providerProfilePreview(preview, httptest.NewRequest(http.MethodPost, "/api/v1/provider-profiles/preview", bytes.NewReader(body)))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"engine_id":"xray"`) || strings.Contains(preview.Body.String(), "123e4567") || strings.Contains(preview.Body.String(), "PUBLICKEY") {
		t.Fatalf("preview=%d %s", preview.Code, preview.Body.String())
	}
	if draft, err := configs.ReadExpert("xray", "main"); err != nil || draft.Source == "staged" {
		t.Fatal("preview wrote a draft")
	}
	body, _ = json.Marshal(map[string]any{"profile": xrayImportURI, "engine": "xray", "confirm": "IMPORT_REMOTE_PROFILE"})
	imported := httptest.NewRecorder()
	a.providerProfileImport(imported, httptest.NewRequest(http.MethodPost, "/api/v1/provider-profiles/import", bytes.NewReader(body)))
	if imported.Code != http.StatusOK || !strings.Contains(imported.Body.String(), `"draft_only":true`) {
		t.Fatalf("import=%d %s", imported.Code, imported.Body.String())
	}
	draft, err := configs.ReadExpert("xray", "main")
	if err != nil || !strings.Contains(draft.Content, `"realitySettings"`) || !strings.Contains(draft.Content, `"xtls-rprx-vision"`) {
		t.Fatalf("xray draft=%+v err=%v", draft, err)
	}
	if other, err := configs.ReadExpert("sing-box", "main"); err != nil || other.Content != singBox {
		t.Fatal("Xray import changed the Sing-box draft")
	}
}

func TestXrayProfileImportRejectsUnsupportedAndUnknownEngine(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	a := &App{EngineConfigs: configs}
	unsupported := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=cdn.example&type=ws&path=/x"
	body, _ := json.Marshal(map[string]any{"profile": unsupported, "engine": "xray", "confirm": "IMPORT_REMOTE_PROFILE"})
	response := httptest.NewRecorder()
	a.providerProfileImport(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"XRAY_UNSUPPORTED_PROFILE"`) {
		t.Fatalf("unsupported=%d %s", response.Code, response.Body.String())
	}
	if draft, err := configs.ReadExpert("xray", "main"); err != nil || draft.Source == "staged" {
		t.Fatal("rejected profile wrote a draft")
	}
	body, _ = json.Marshal(map[string]any{"profile": xrayImportURI, "engine": "mihomo", "confirm": "IMPORT_REMOTE_PROFILE"})
	response = httptest.NewRecorder()
	a.providerProfileImport(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown engine accepted: %d", response.Code)
	}
}
