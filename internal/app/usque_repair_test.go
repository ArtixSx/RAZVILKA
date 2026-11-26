package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type appUSQUERunner struct {
	initPath string
}

func (runner appUSQUERunner) Run(_ context.Context, command usquediag.Command) ([]byte, error) {
	if command.Name == "/bin/sh" && len(command.Args) == 2 && command.Args[0] == "-n" && command.Args[1] == runner.initPath {
		return []byte("syntax ok"), nil
	}
	if command.Name == "/bin/ndmc" {
		if len(command.Env) == 0 {
			return nil, errors.New("synthetic Entware library conflict")
		}
		return []byte("Keenetic"), nil
	}
	return nil, errors.New("unexpected command")
}

func appUSQUEManager(t *testing.T, init string) (*usquediag.Manager, string) {
	t.Helper()
	root := t.TempDir()
	initPath := filepath.Join(root, "S51usque")
	if err := os.WriteFile(initPath, []byte(init), 0o755); err != nil {
		t.Fatal(err)
	}
	return &usquediag.Manager{
		Runner:     appUSQUERunner{initPath: initPath},
		InitPath:   initPath,
		NDMCPath:   "/bin/ndmc",
		ShellPath:  "/bin/sh",
		RepairRoot: filepath.Join(root, "repair"),
	}, initPath
}

func TestUSQUERepairEndpointRequiresConfirmationAndAppliesBoundedPatch(t *testing.T) {
	manager, initPath := appUSQUEManager(t, "#!/bin/sh\n/bin/ndmc -c 'show version'\n")
	a := &App{USQUE: manager}

	missing := httptest.NewRecorder()
	a.usqueRepair(missing, httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/usque/repair", strings.NewReader(`{"confirm":"wrong"}`)))
	if missing.Code != http.StatusPreconditionRequired || !strings.Contains(missing.Body.String(), "USQUE_REPAIR_CONFIRMATION_REQUIRED") {
		t.Fatalf("missing confirmation response=%d %s", missing.Code, missing.Body.String())
	}

	applied := httptest.NewRecorder()
	a.usqueRepair(applied, httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/usque/repair", strings.NewReader(`{"confirm":"REPAIR_USQUE_NDMC"}`)))
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), `"changed":true`) {
		t.Fatalf("repair response=%d %s", applied.Code, applied.Body.String())
	}
	data, err := os.ReadFile(initPath)
	if err != nil || strings.Count(string(data), "LD_LIBRARY_PATH=/lib:/usr/lib /bin/ndmc") != 1 {
		t.Fatalf("unexpected repaired init: %v %q", err, data)
	}
}

func TestUSQUERepairEndpointRejectsAmbiguousInit(t *testing.T) {
	manager, _ := appUSQUEManager(t, "#!/bin/sh\nNDMC=/bin/ndmc\n$NDMC -c 'show version'\n")
	a := &App{USQUE: manager}
	response := httptest.NewRecorder()
	a.usqueRepair(response, httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/usque/repair", strings.NewReader(`{"confirm":"REPAIR_USQUE_NDMC"}`)))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "USQUE_REPAIR_BLOCKED") {
		t.Fatalf("ambiguous repair response=%d %s", response.Code, response.Body.String())
	}
}

func TestUSQUERepairEndpointUsesExclusiveOperationGate(t *testing.T) {
	a := &App{}
	release, err := a.Operations.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	called := false
	handler := a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/usque/repair", nil))
	if called || response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "RESTORE_OPERATION_BUSY") {
		t.Fatalf("repair was not exclusive: called=%v response=%d %s", called, response.Code, response.Body.String())
	}
	if _, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("shared admission unexpectedly disappeared", err)
	}
}
