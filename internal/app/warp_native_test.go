package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/warp"
)

func TestWARPNativePendingAPINeverAdvertisesRetryOrLeaksCheckpoint(t *testing.T) {
	dir := t.TempDir()
	manager := warp.New(filepath.Join(dir, "warp"), filepath.Join(dir, "backup"), engineconfig.New(filepath.Join(dir, "stage"), filepath.Join(dir, "config-backup")))
	native := filepath.Join(manager.Root, "native-enrollment")
	if err := os.MkdirAll(native, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(map[string]any{"schema": 1, "directory": "attempt-" + strings.Repeat("a", 32), "created_at": time.Now().UTC()})
	if err := os.WriteFile(filepath.Join(native, "pending.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{Warp: manager}
	response := httptest.NewRecorder()
	a.warpAction(response, httptest.NewRequest(http.MethodPost, "/api/v1/warp/generate", strings.NewReader(`{"fresh":true,"accept_tos":true}`)))
	if response.Code != http.StatusConflict {
		t.Fatalf("pending HTTP status=%d", response.Code)
	}
	var payload struct {
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Code != "WARP_REGISTRATION_PENDING" || payload.Retryable {
		t.Fatalf("pending API policy=%+v err=%v", payload, err)
	}
	if strings.Contains(response.Body.String(), "attempt-") || strings.Contains(response.Body.String(), manager.Root) {
		t.Fatal("pending API leaked private checkpoint path")
	}
}
