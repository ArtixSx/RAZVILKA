package panelhealth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestAvailabilityWhileWorkerOwnsAdmission(t *testing.T) {
	var gate operationgate.Gate
	release, err := gate.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	srv := httptest.NewServer(Handler(&gate))
	defer srv.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Get(srv.URL + Path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatal(res.Status)
	}
	var value response
	if err := json.NewDecoder(res.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.Panel != "responding" || value.Dataplane != "not-checked" || value.Admission.State != "busy" {
		t.Fatalf("invalid claims: %+v", value)
	}
	if _, err := gate.Enter(context.Background()); err != operationgate.ErrBusy {
		t.Fatalf("liveness released the worker: %v", err)
	}
}

func TestFencedGateStillAnswersWithoutGrantingPermission(t *testing.T) {
	var gate operationgate.Gate
	gate.Fence()
	w := httptest.NewRecorder()
	Handler(&gate).ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"recovery-required"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := gate.Exclusive(context.Background()); err != operationgate.ErrRecovery {
		t.Fatal("recovery fence bypassed")
	}
}

func TestAvailabilityMethodAndCacheContract(t *testing.T) {
	var gate operationgate.Gate
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			Handler(&gate).ServeHTTP(w, httptest.NewRequest(method, Path, nil))
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("private liveness must not be cached")
			}
			if method == http.MethodGet {
				if w.Code != 200 || w.Body.Len() == 0 {
					t.Fatal("GET failed")
				}
				return
			}
			if method == http.MethodHead {
				if w.Code != 200 || w.Body.Len() != 0 {
					t.Fatal("HEAD failed")
				}
				return
			}
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || w.Body.Len() != 0 {
				t.Fatal("write-like method not rejected")
			}
		})
	}
}

func TestAvailabilityUnavailableDependency(t *testing.T) {
	w := httptest.NewRecorder()
	Handler(nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
	if w.Code != 503 {
		t.Fatal("nil dependency must not certify liveness")
	}
}

func TestAvailabilityConcurrentReadsDuringBlockedWork(t *testing.T) {
	var gate operationgate.Gate
	release, err := gate.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	handler := Handler(&gate)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
				if w.Code != 200 || !strings.Contains(w.Body.String(), `"dataplane":"not-checked"`) {
					t.Error("lost independent liveness")
					return
				}
			}
		}()
	}
	wg.Wait()
	if gate.Snapshot().State != "busy" {
		t.Fatal("worker was canceled or released")
	}
}

func TestAvailabilityDoesNotDiscloseConfigurationOrRouteClaims(t *testing.T) {
	var gate operationgate.Gate
	w := httptest.NewRecorder()
	Handler(&gate).ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
	var value map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"schema": true, "name": true, "panel": true, "dataplane": true, "admission": true}
	for key := range value {
		if !allowed[key] {
			t.Fatalf("unexpected public field: %s", key)
		}
	}
	for _, forbidden := range []string{"token", "password", "node_id", "service_id", "endpoint", "live_active", "healthy", "true_route", "PASS"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("forbidden field/claim: %s", forbidden)
		}
	}
}
