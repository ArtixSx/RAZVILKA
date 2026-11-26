package app

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/warp"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func nativeBackupApp(t *testing.T) (*App, string) {
	t.Helper()
	a, root := privateRestoreTestApp(t)
	a.PrivateRestore.Close()
	a.Warp = warp.New(filepath.Join(root, "warp"), filepath.Join(root, "warp-backup"), a.EngineConfigs)
	c, _, err := privaterestore.Open(context.Background(), privaterestore.Layout{Config: filepath.Join(root, "config.json"), CustomServices: filepath.Join(root, "custom.json"), Devices: filepath.Join(root, "devices.json"), StageRoot: a.EngineConfigs.StageRoot, ProviderRoot: filepath.Join(root, "provider"), WarpRoot: a.Warp.Root, JournalRoot: filepath.Join(root, "native-journal")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.StartRuntime(); err != nil {
		t.Fatal(err)
	}
	a.PrivateRestore = c
	return a, root
}
func TestNativeEncryptedHTTPBackupRestoreRetainsPendingAndAppliedSettings(t *testing.T) {
	source, _ := nativeBackupApp(t)
	d := nativeenrollment.Document{Schema: 1}
	id := "attempt-" + strings.Repeat("a", 32)
	d.Set("pending.json", []byte(`{"schema":1,"directory":"`+id+`","created_at":"2026-09-01T00:00:00Z","fresh":false}`))
	d.Set(id+"/private-key.bin", []byte{0, 1, 255, 0})
	d.Set(id+"/response.private.json", []byte("private provider token"))
	target, err := nativeenrollment.Open(source.Warp.Root)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := target.Read(context.Background())
	if _, err := target.Save(context.Background(), before, d); err != nil {
		t.Fatal(err)
	}
	target.Close()
	export := httptest.NewRecorder()
	source.Handler(http.NotFoundHandler()).ServeHTTP(export, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/export", strings.NewReader(`{"password":"correct horse battery staple"}`)))
	if export.Code != http.StatusOK || strings.Contains(export.Body.String(), "private provider") {
		t.Fatalf("native backup export failed: HTTP %d", export.Code)
	}
	var envelope privatebackup.Envelope
	if json.Unmarshal(export.Body.Bytes(), &envelope) != nil {
		t.Fatal("invalid envelope")
	}
	p, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || p.NativeEnrollment == nil {
		t.Fatal("encrypted HTTP backup omitted native checkpoint", err)
	}
	restored, _ := nativeBackupApp(t)
	applied := restored.Store.Get().AppliedServices
	body, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "correct horse battery staple", "confirm": "IMPORT_PRIVATE_BACKUP"})
	for _, path := range []string{"preview", "import"} {
		rec := httptest.NewRecorder()
		restored.Handler(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/"+path, bytes.NewReader(body)))
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "private provider") || strings.Contains(rec.Body.String(), id) {
			t.Fatalf("native backup %s failed or leaked: HTTP %d", path, rec.Code)
		}
	}
	got, err := restored.Warp.ExportNativePrivateIfPresent(context.Background())
	if err != nil || got == nil || !bytes.Equal(got.Content, p.NativeEnrollment.Content) {
		t.Fatal("HTTP restore lost original native material", err)
	}
	if !reflect.DeepEqual(applied, restored.Store.Get().AppliedServices) || restored.Warp.Status(context.Background()).CandidateStaged {
		t.Fatal("native restore activated/staged profile or changed applied routes")
	}
}
