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

func TestPartialProviderImportRequiresReviewedAcceptance(t *testing.T) {
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	a := &App{EngineConfigs: configs}
	const original = `{"outbounds":[{"type":"direct","tag":"original"}]}`
	if _, err := configs.Stage("sing-box", "main", original); err != nil {
		t.Fatal(err)
	}
	const bad = "vless://123e4567-e89b-12d3-a456-426614174999@rejected.example:443?type=xhttp"
	const good = "vless://123e4567-e89b-12d3-a456-426614174000@good.example:443?security=tls"
	for _, accept := range []bool{false, true} {
		body, _ := json.Marshal(map[string]any{"profile": bad + "\n" + good, "confirm": "IMPORT_REMOTE_PROFILE", "accept_partial": accept})
		response := httptest.NewRecorder()
		a.providerProfileImport(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		want := http.StatusPreconditionRequired
		if accept {
			want = http.StatusOK
		}
		if response.Code != want || !strings.Contains(response.Body.String(), `"rejected"`) || strings.Contains(response.Body.String(), "426614174999") {
			t.Fatalf("response %d: %s", response.Code, response.Body.String())
		}
		content, err := configs.ReadExpert("sing-box", "main")
		if err != nil {
			t.Fatal(err)
		}
		if !accept && content.Content != original {
			t.Fatal("unreviewed partial import changed draft")
		}
		if accept && (!strings.Contains(content.Content, "good.example") || strings.Contains(content.Content, "rejected.example")) {
			t.Fatal("wrong nodes saved")
		}
	}
	before, _ := configs.ReadExpert("sing-box", "main")
	body, _ := json.Marshal(map[string]any{"profile": bad, "confirm": "IMPORT_REMOTE_PROFILE", "accept_partial": true})
	response := httptest.NewRecorder()
	a.providerProfileImport(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	after, _ := configs.ReadExpert("sing-box", "main")
	if response.Code != http.StatusBadRequest || before.Content != after.Content {
		t.Fatal("all-invalid import replaced draft")
	}
}
