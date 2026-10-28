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
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func nfqws2HookAdmissionRequest(a *App, ctx context.Context, calls *int) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { *calls++; w.WriteHeader(http.StatusOK) }))
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/autonomy", nil).WithContext(ctx))
	return w
}
func assertNFQWS2HookAdmissionRefusal(t *testing.T, w *httptest.ResponseRecorder, status int, code string, recovery bool) {
	t.Helper()
	var body struct {
		Code       string `json:"code"`
		Recovery   bool   `json:"recovery_required"`
		NotStarted bool   `json:"not_started"`
		Live       bool   `json:"live_applied"`
		Error      string `json:"error"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != status || body.Code != code || body.Recovery != recovery || !body.NotStarted || body.Live {
		t.Fatalf("unexpected admission refusal: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(body.Error, "PRIVATE") || strings.Contains(body.Error, "перезапуск") {
		t.Fatal("raw cause or forced restart instruction exposed")
	}
}

func TestNFQWS2HookAdmissionPendingThenLegitimateSettlement(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	started, allow := make(chan struct{}), make(chan struct{})
	releaseRestore := sync.OnceFunc(func() { close(allow) })
	model.restore = func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error) {
		close(started)
		<-allow
		return dataplane.NFQWS2HookRestore{Restored: []int{4}, Instance: model.instance}, nil
	}
	done := make(chan struct{})
	var restoreErr error
	go func() { defer close(done); restoreErr = a.restoreNFQWS2HooksRound(context.Background(), time.Now()) }()
	defer func() { releaseRestore(); <-done }()
	<-started
	path := filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	w := nfqws2HookAdmissionRequest(a, context.Background(), &calls)
	assertNFQWS2HookAdmissionRefusal(t, w, http.StatusServiceUnavailable, "DATAPLANE_RECOVERY_REQUIRED", true)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || calls != 0 || model.restored != 1 {
		t.Fatal("GET ran handler, changed journal, or started another restoration")
	}
	releaseRestore()
	<-done
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if err := CheckNFQWS2HookRecovery(a.Dataplane.StateRoot); err != nil {
		t.Fatal("legitimate restoration did not settle journal", err)
	}
	w = nfqws2HookAdmissionRequest(a, context.Background(), &calls)
	if w.Code != http.StatusOK || calls != 1 {
		t.Fatal("fresh GET not admitted after legitimate settlement")
	}
}

func TestNFQWS2HookAdmissionMalformedOrCrashedJournalRemainsDenied(t *testing.T) {
	for _, mode := range []string{"malformed", "crashed-pending"} {
		t.Run(mode, func(t *testing.T) {
			a, plan, model := nfqws2HookAppFixture(t)
			owner, err := beginNFQWS2HookJournal(a.Dataplane.StateRoot, plan, model.instance)
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.root.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(a.Dataplane.StateRoot, nfqws2HookJournalName)
			if mode == "malformed" {
				if err := os.WriteFile(path, []byte("{PRIVATE_CORRUPT_JOURNAL"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			restarted := &App{Dataplane: dataplane.New(a.Dataplane.StateRoot)}
			if err := restarted.InitializeComponentRecoveryGate(); err != nil {
				t.Fatal(err)
			}
			calls := 0
			for i := 0; i < 2; i++ {
				w := nfqws2HookAdmissionRequest(restarted, context.Background(), &calls)
				assertNFQWS2HookAdmissionRefusal(t, w, http.StatusServiceUnavailable, "DATAPLANE_RECOVERY_REQUIRED", true)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) || calls != 0 || model.restored != 0 || model.observed != 0 {
				t.Fatal("GET modified or bypassed unknown durable recovery")
			}
			if !errors.Is(CheckNFQWS2HookRecovery(a.Dataplane.StateRoot), ErrNFQWS2HookRecovery) {
				t.Fatal("unknown journal protection weakened")
			}
		})
	}
}

func TestNFQWS2HookAdmissionCancellationAndBusyKeepTheirCodes(t *testing.T) {
	a := &App{}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	calls := 0
	w := nfqws2HookAdmissionRequest(a, context.Background(), &calls)
	assertNFQWS2HookAdmissionRefusal(t, w, http.StatusConflict, "RESTORE_OPERATION_BUSY", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = nfqws2HookAdmissionRequest(a, ctx, &calls)
	assertNFQWS2HookAdmissionRefusal(t, w, http.StatusRequestTimeout, "OPERATION_CANCELED", false)
	if calls != 0 {
		t.Fatal("refused GET executed handler")
	}
}
