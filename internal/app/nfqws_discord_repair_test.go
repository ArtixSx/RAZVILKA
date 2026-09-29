package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestNFQWSDiscordRepairStagesDraftOnly(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	const old = "NFQWS_ARGS=\"--filter-tcp=443 --filter-l7=tls\"\nUDP_PORTS=443\n"
	if _, err := configs.Stage("nfqws2", "main", old); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, EngineConfigs: configs}
	read := httptest.NewRecorder()
	a.nfqwsSetupMode(read, httptest.NewRequest(http.MethodGet, "/api/v1/nfqws2/setup-mode", nil))
	var view engineconfig.NFQWSModeView
	if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &view) != nil || view.DiscordVoice {
		t.Fatalf("view=%d %s", read.Code, read.Body.String())
	}
	put := func(review, confirm string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		body := fmt.Sprintf(`{"review":%q,"config_revision":%d,"confirm":%q}`, review, store.Get().Revision, confirm)
		a.nfqwsDiscordRepair(w, httptest.NewRequest(http.MethodPut, "/api/v1/nfqws2/discord-repair", strings.NewReader(body)))
		return w
	}
	if w := put(view.Review, "WRONG"); w.Code != 400 {
		t.Fatalf("unconfirmed repair accepted: %d", w.Code)
	}
	if w := put("0000", "STAGE_DISCORD_REPAIR"); w.Code != 409 {
		t.Fatalf("stale review accepted: %d", w.Code)
	}
	w := put(view.Review, "STAGE_DISCORD_REPAIR")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"discord_voice":true`) || !strings.Contains(w.Body.String(), `"live_applied":false`) {
		t.Fatalf("repair=%d %s", w.Code, w.Body.String())
	}
	draft, err := configs.ReadExpert("nfqws2", "main")
	if err != nil || draft.Source != "staged" || !strings.Contains(draft.Content, engineconfig.DiscordRepairProfile) {
		t.Fatalf("draft=%+v err=%v", draft, err)
	}
}
