package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/profileexchange"
)

func TestPublicProfilePreviewMatchesImportedServiceScope(t *testing.T) {
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	custom, err := customservices.Load(filepath.Join(root, "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, CustomServices: custom, EngineConfigs: engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups")), Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video"}}}}
	a.EngineConfigs.LiveRoot = filepath.Join(root, "live")
	old := config.ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.0.2.2", "192.0.2.3"}}
	if err := store.UpdateService("video", old); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	original := store.Get()
	handler := a.Handler(http.NotFoundHandler())
	post := func(path string, value any, code int) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/profiles/"+path, bytes.NewReader(data)))
		if w.Code != code {
			t.Fatalf("%s returned %d: %s", path, w.Code, w.Body.String())
		}
		return w
	}
	for _, tc := range []struct {
		name, action string
		incoming     []string
		wantAfter    []string
	}{
		{"order_aliases_duplicates", "unchanged", []string{"192.0.2.3", "192.0.2.2/32", "192.0.2.2"}, old.Sources},
		{"narrow", "change", []string{"192.0.2.9"}, []string{"192.0.2.9"}},
		{"expand_to_all", "change", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := profileexchange.New("fixture", "Scope", "", "")
			b.Services["video"] = config.ServiceState{Enabled: true, Mode: "auto", Sources: tc.incoming}
			if err := profileexchange.Seal(&b); err != nil {
				t.Fatal(err)
			}
			w := post("preview", b, http.StatusOK)
			var preview struct {
				Changes []struct {
					Action string
					Before []string `json:"sources_before"`
					After  []string `json:"sources_after"`
				} `json:"service_changes"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
				t.Fatal(err)
			}
			if len(preview.Changes) != 1 {
				t.Fatal(preview)
			}
			change := preview.Changes[0]
			wantAfter, err := config.NormalizeSources(tc.wantAfter)
			if err != nil {
				t.Fatal(err)
			}
			if change.Action != tc.action || !reflect.DeepEqual(change.Before, original.Services["video"].Sources) || !reflect.DeepEqual(change.After, wantAfter) {
				t.Fatalf("unexpected preview: %+v", change)
			}
			if !reflect.DeepEqual(store.Get(), original) {
				t.Fatal("preview modified config")
			}
			if tc.name == "expand_to_all" {
				post("import", map[string]any{"bundle": b}, http.StatusOK)
				committed := store.Get()
				if !reflect.DeepEqual(committed.Services["video"].Sources, change.After) || !reflect.DeepEqual(committed.AppliedServices, original.AppliedServices) || committed.AppliedRevision != original.AppliedRevision {
					t.Fatal("draft/snapshot mismatch")
				}
			}
		})
	}

	b := profileexchange.New("fixture", "Invalid", "", "")
	for _, invalid := range []config.ServiceState{
		{Route: "auto", Sources: []string{"invalid source"}},
		{Route: "auto", WireGuardProfileRevision: strings.Repeat("a", 64)},
	} {
		b.Services["video"] = invalid
		if err := profileexchange.Seal(&b); err != nil {
			t.Fatal(err)
		}
		before := store.Get()
		post("preview", b, http.StatusBadRequest)
		post("import", map[string]any{"bundle": b}, http.StatusBadRequest)
		if !reflect.DeepEqual(before, store.Get()) {
			t.Fatal("invalid bundle modified config")
		}
	}

	t.Run("reviewed binding and intervening scope edit", func(t *testing.T) {
		localRevision := strings.Repeat("b", 64)
		if err := store.UpdateService("video", config.ServiceState{Enabled: true, Route: "wireguard:local", WireGuardProfileRevision: localRevision}); err != nil {
			t.Fatal(err)
		}
		b := profileexchange.New("fixture", "Migration", "", "")
		b.Services["video"] = config.ServiceState{Enabled: true, Route: "auto"}
		b.CustomServices = []catalog.Service{{ID: "custom-local", Name: "Local", Category: "Custom", Domains: []string{"fixture.example.org"}, Strategy: []string{"auto"}}}
		content := "fixture.example.org\n"
		b.EngineFiles = []profileexchange.EngineFile{{EngineID: "nfqws2", FileID: "user-list", Content: content, SHA256: profileexchange.Sum([]byte(content))}}
		if err := profileexchange.Seal(&b); err != nil {
			t.Fatal(err)
		}
		readPreview := func() profilePreviewResult {
			t.Helper()
			w := post("preview", b, http.StatusOK)
			var preview profilePreviewResult
			if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
				t.Fatal(err)
			}
			if preview.DraftRevision != store.Get().Revision || len(preview.ServiceChanges) != 1 {
				t.Fatal(preview)
			}
			return preview
		}
		preview := readPreview()
		change := preview.ServiceChanges[0]
		if change["action"] != "change" || change["route_before"] != "wireguard:local" || change["route_after"] != "auto" || change["wireguard_profile_revision_before"] != localRevision || change["wireguard_profile_revision_after"] != "" {
			t.Fatal(change)
		}
		request := map[string]any{"bundle": b, "expected_revision": preview.DraftRevision}

		held, err := a.Operations.Enter(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(request)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		blocked := httptest.NewRecorder()
		handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodPost, "/api/v1/profiles/import", bytes.NewReader(body)).WithContext(ctx))
		cancel()
		held()
		if blocked.Code == http.StatusOK || store.Get().Revision != preview.DraftRevision {
			t.Fatalf("import admitted during shared operation: %d", blocked.Code)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/services/video", strings.NewReader(`{"enabled":true,"route":"auto","sources":["192.0.2.42"]}`)))
		if w.Code != http.StatusOK {
			t.Fatalf("independent edit: %d %s", w.Code, w.Body.String())
		}
		edited := store.Get()
		stale := post("import", request, http.StatusConflict)
		if !strings.Contains(stale.Body.String(), "PROFILE_DRAFT_CHANGED") || !reflect.DeepEqual(store.Get(), edited) || a.CustomServices.Has("custom-local") {
			t.Fatal("stale preview changed configuration or custom services")
		}
		engineFile, err := a.EngineConfigs.Read("nfqws2", "user-list")
		if err != nil || engineFile.Source != "missing" {
			t.Fatalf("stale import staged engine file: %v %v", engineFile, err)
		}

		request["expected_revision"] = readPreview().DraftRevision
		post("import", request, http.StatusOK)
		after := store.Get()
		if !a.CustomServices.Has("custom-local") || after.Services["video"].Sources != nil || after.Services["video"].WireGuardProfileRevision != "" || !reflect.DeepEqual(after.AppliedServices, edited.AppliedServices) {
			t.Fatal("reviewed import mismatch")
		}
		engineFile, err = a.EngineConfigs.Read("nfqws2", "user-list")
		if err != nil || engineFile.Source != "staged" || engineFile.Content != content {
			t.Fatal("reviewed engine draft missing")
		}
		if err := store.UpdateService("video", config.ServiceState{Enabled: true, Route: "wireguard:local", WireGuardProfileRevision: localRevision}); err != nil {
			t.Fatal(err)
		}
		request["expected_revision"] = readPreview().DraftRevision
		request["allow_custom_updates"] = true
		post("import", request, http.StatusOK)
		if state := store.Get().Services["video"]; state.Route != "auto" || state.WireGuardProfileRevision != "" {
			t.Fatal("local WireGuard binding was retained after importing AUTO")
		}
	})
}
