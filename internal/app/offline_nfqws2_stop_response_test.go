//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestOfflineNFQWS2StopHTTPReportsRecoveryWithoutOpeningMutation(t *testing.T) {
	for _, state := range []string{"pending", "malformed"} {
		t.Run(state, func(t *testing.T) {
			// Create the real outer WAL through its controller. Native evidence
			// is modeled by the existing fixture; no native Stop is reached.
			f := newOfflineNFQStopModel(t)
			native := f.native(t)
			interrupted := errors.New("modeled exit after durable Stop intent")
			native.checkpoint = func(stage string) error {
				if stage == "intent" {
					return interrupted
				}
				return nil
			}
			if result, err := f.run(t, native); !errors.Is(err, interrupted) || result.Stopped {
				t.Fatal("pending controller intent was not reached", err)
			}
			walPath := filepath.Join(f.state, dataplane.NFQWS2OfflineStopJournalName)
			if state == "malformed" {
				if err := os.WriteFile(walPath, []byte(`{"PRIVATE_INCOMPLETE_STOP":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := map[string][]byte{}
			for _, path := range []string{walPath, f.configPath, filepath.Join(f.state, nfqws2HookJournalName), filepath.Join(f.state, "nfqws2-boot-hooks.json")} {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path] = raw
			}
			// An already running app with another selected state directory must
			// still report the fixed installation's actual outer recovery fence.
			a := &App{Dataplane: dataplane.New(t.TempDir())}
			if err := a.initializeComponentRecoveryGate(f.state); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusOK)
			}))
			for _, request := range []struct{ method, path string }{{http.MethodGet, "/api/v1/autonomy"}, {http.MethodPost, "/api/v1/apply"}} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(request.method, request.path, nil).WithContext(ctx))
				assertNFQWS2HookAdmissionRefusal(t, w, http.StatusServiceUnavailable, "DATAPLANE_RECOVERY_REQUIRED", true)
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !strings.Contains(body.Error, "-stop-owned-routes") || strings.Contains(body.Error, f.state) || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("outer Stop response omitted its recovery action or exposed private state", err)
				}
			}
			if calls != 0 || f.stopCalls != 0 || f.activations != 0 || f.retries != 0 {
				t.Fatal("a recovery response granted handler or native control admission")
			}
			for path, expected := range before {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("HTTP recovery response altered retained state", err)
				}
			}
		})
	}
}
