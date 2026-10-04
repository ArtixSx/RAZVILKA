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

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestManualNodeImportAdmitsTypedMaterialBeforeUncheckedXHTTPWrite(t *testing.T) {
	for _, xhttp := range []bool{false, true} {
		for _, mode := range []string{"missing", "reader2", "reader3", "panic", "cancel-nil"} {
			t.Run(strings.Join([]string{map[bool]string{false: "raw", true: "xhttp"}[xhttp], mode}, "/"), func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "nodes")
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
				store, err := nodestore.Open(root)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { store.Close() })
				now := time.Now()
				before, err := store.Import(context.Background(), nodestore.Source{ID: "existing", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174001@existing.example:443?security=tls", now, time.Hour, false)
				if err != nil {
					t.Fatal(err)
				}
				privatePath := filepath.Join(root, "nodes.private.json")
				beforeBytes, err := os.ReadFile(privatePath)
				if err != nil {
					t.Fatal(err)
				}
				a := &App{Nodes: store}
				uri := "vless://123e4567-e89b-12d3-a456-426614174000@incoming-private.example:443?security=tls&sni=front.example"
				wanted := 1
				if xhttp {
					uri += "&type=xhttp&mode=stream-one&path=%2Fincoming-private"
					wanted = 3
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				if mode != "missing" {
					a.NodeHistoryWriteGuard = func(c context.Context, required int) error {
						calls++
						if required != wanted {
							t.Fatal("incoming material has incorrect minimum", required)
						}
						current, err := store.Snapshot(c, now)
						if err != nil || current.Generation != before.Generation || len(current.Nodes) != 1 {
							t.Fatal("guard held Store lock or ran after import", err)
						}
						if release, err := a.Operations.Exclusive(c); !errors.Is(err, operationgate.ErrBusy) {
							if release != nil {
								release()
							}
							t.Fatal("manual guard lost operation admission", err)
						}
						switch mode {
						case "reader2":
							if required > 2 {
								return errors.New("incoming-private.example reader2 refused")
							}
						case "panic":
							panic("incoming-private.example panic")
						case "cancel-nil":
							cancel()
						}
						return nil
					}
				}
				body, err := json.Marshal(map[string]any{"profile": uri, "confirm": "STORE_REMOTE_NODES"})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/import", bytes.NewReader(body)).WithContext(ctx)
				w := httptest.NewRecorder()
				a.Handler(http.NotFoundHandler()).ServeHTTP(w, request)
				allowed := mode == "reader3" || mode == "reader2" && !xhttp || mode == "missing" && !xhttp
				if allowed {
					if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"total_nodes":2`) {
						t.Fatal("compatible manual import refused", w.Code)
					}
					if required, err := store.RequiredHistoryReadVersion(context.Background()); err != nil || required != wanted {
						t.Fatal("unchecked import lost material reader fence", required, err)
					}
				} else {
					afterBytes, err := os.ReadFile(privatePath)
					if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "NODE_HISTORY_ADMISSION_REQUIRED") || err != nil || !bytes.Equal(beforeBytes, afterBytes) {
						t.Fatal("unsafe manual import did not refuse before write", w.Code, err)
					}
				}
				for _, private := range []string{"incoming-private", "123e4567", "front.example"} {
					if strings.Contains(w.Body.String(), private) {
						t.Fatal("private import admission details escaped")
					}
				}
				wantCalls := 1
				if mode == "missing" {
					wantCalls = 0
				}
				if calls != wantCalls {
					t.Fatal("manual admission probe replayed", calls)
				}
			})
		}
	}
}
