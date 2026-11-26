package main

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestCleanInstallControlFailureDiagnosticIsClosedAndRetainsMaskedDeadline(t *testing.T) {
	secret := errors.New("private config value and installation path must not be logged")
	for _, tc := range []struct {
		name            string
		err, contextErr error
		want            string
	}{
		{"native-refusal", operationgate.ErrSelfUpdateStopJournal, nil, "CLEAN_INSTALL_CONTROL_REFUSED"},
		{"stopped", operationgate.ErrSelfUpdateStopped, nil, "CLEAN_INSTALL_CONTROL_REFUSED"},
		{"changed", operationgate.ErrSelfUpdateStopChanged, nil, "CLEAN_INSTALL_CONTROL_REFUSED"},
		{"private-error", secret, nil, "CLEAN_INSTALL_CONTROL_REFUSED"},
		{"deadline", context.DeadlineExceeded, nil, "CLEAN_INSTALL_CONTROL_DEADLINE"},
		{"wrapped-deadline", fmt.Errorf("private details: %w", context.DeadlineExceeded), nil, "CLEAN_INSTALL_CONTROL_DEADLINE"},
		{"joined-deadline", errors.Join(secret, context.DeadlineExceeded), nil, "CLEAN_INSTALL_CONTROL_DEADLINE"},
		{"masked-deadline", operationgate.ErrSelfUpdateStopJournal, context.DeadlineExceeded, "CLEAN_INSTALL_CONTROL_DEADLINE"},
		{"text-is-not-deadline", errors.New("context deadline exceeded"), nil, "CLEAN_INSTALL_CONTROL_REFUSED"},
		{"canceled", context.Canceled, context.Canceled, "CLEAN_INSTALL_CONTROL_REFUSED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cleanInstallControlFailureCategory(tc.err, tc.contextErr); got != tc.want {
				t.Fatalf("diagnostic=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestCleanInstallControlDispatchExactArgsAndNoPathOverrides(t *testing.T) {
	base := t.TempDir()
	roots := selfUpdateReadRoots(base)
	sha := strings.Repeat("a", 64)
	before := selfUpdateReadTree(t, base)
	for _, test := range []struct {
		args    []string
		handled bool
		code    int
	}{
		{nil, false, 0}, {[]string{"INSTALL-CONTROL-INITIALIZE", sha}, false, 0},
		{[]string{cleanInstallControlCommand}, true, 2},
		{[]string{cleanInstallControlCommand, sha, base}, true, 2},
		{[]string{cleanInstallControlCommand, " " + sha}, true, 2},
		{[]string{cleanInstallControlCommand, strings.ToUpper(sha)}, true, 2},
		{[]string{cleanInstallControlCommand, strings.Repeat("a", 63)}, true, 2},
		{[]string{cleanInstallControlCommand, sha}, true, 3},
	} {
		handled, code := runCleanInstallControlCommand(test.args, roots)
		if handled != test.handled || code != test.code || !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
			t.Fatal("closed installer dispatch accepted args/roots or changed model files", handled, code)
		}
	}
	if handled, code := runCommandWithSelfUpdateJournalRoots([]string{cleanInstallControlCommand, sha}, roots); !handled || code != 3 {
		t.Fatal("Main dispatch missed closed production-root refusal", handled, code)
	}
}

func TestCleanInstallControlConfigIsDenialOnlyUnappliedSafeBaseline(t *testing.T) {
	for _, test := range []struct {
		raw     string
		allowed bool
	}{
		{`{"schema_version":1,"safe_mode":true,"services":{},"applied_services":{}}`, true},
		// Safe Mode is retired: a clean baseline no longer needs the flag.
		{`{"schema_version":1,"safe_mode":false}`, true},
		{`{"schema_version":1,"services":{},"applied_services":{}}`, true},
		{`{"schema_version":1,"safe_mode":true,"service_control":{"mode":"manual","stopped":true}}`, false},
		{`{"schema_version":1,"safe_mode":true,"services":{"telegram":{"enabled":true}}}`, false},
		{`{"schema_version":1,"safe_mode":true,"applied_services":{"telegram":{"enabled":true}}}`, false},
		{`{"schema_version":1,"safe_mode":true,"network_policy":{"schema":2}}`, false},
		{`{"schema_version":1,"safe_mode":true,"default_route_consent":{"schema":2}}`, false},
		{`{"schema_version":1,"safe_mode":true,"applied_network_policy":{"schema":2}}`, false},
		{`{"schema_version":999,"safe_mode":true}`, false}, {`not-json`, false},
	} {
		if cleanInstallConfigUnapplied([]byte(test.raw)) != test.allowed {
			t.Fatal("clean configuration denial changed", test.allowed)
		}
	}
}

func cleanInstallTestContext(t *testing.T) (context.Context, *operationgate.Gate) {
	t.Helper()
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	gate := &operationgate.Gate{}
	ctx, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return ctx, gate
}

func TestCleanInstallControlLedgerActualCreationAndSameReadyIdempotence(t *testing.T) {
	// Actual protected ledger operations in a temp model. This is not the
	// production native installed-image issuer or Linux durability evidence.
	base := t.TempDir()
	path := filepath.Join(base, "control")
	ctx, gate := cleanInstallTestContext(t)
	if err := initializeCleanInstallControlLedger(ctx, gate, path); err != nil {
		t.Fatal(err)
	}
	ready, present, err := operationgate.ReadSelfUpdateStop(ctx, path)
	if err != nil || !present || ready.Stopped || ready.State != "ready" || ready.Sequence != 1 {
		t.Fatal("actual ready ledger unavailable", err)
	}
	before := selfUpdateReadTree(t, base)
	marker, _ := os.Stat(filepath.Join(path, ".control.lock"))
	record, _ := os.Stat(filepath.Join(path, "current-v1.json"))
	if err := initializeCleanInstallControlLedger(ctx, gate, path); err != nil {
		t.Fatal(err)
	}
	after, _, err := operationgate.ReadSelfUpdateStop(ctx, path)
	markerAfter, _ := os.Stat(filepath.Join(path, ".control.lock"))
	recordAfter, _ := os.Stat(filepath.Join(path, "current-v1.json"))
	if err != nil || after != ready || !os.SameFile(marker, markerAfter) || !os.SameFile(record, recordAfter) ||
		!reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("idempotence renewed or rewrote the ready owner")
	}
}

func TestCleanInstallControlLedgerPreservesStoppedAndPartialOwners(t *testing.T) {
	for _, mode := range []string{"stopped", "empty", "missing-marker", "missing-current", "bad-marker", "unknown-current", "wrong-type"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "control")
			ctx, gate := cleanInstallTestContext(t)
			if mode == "wrong-type" {
				if err := os.WriteFile(path, []byte("retained owner"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if mode == "empty" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := operationgate.InitializeSelfUpdateControl(ctx, path); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "stopped":
					if _, err := operationgate.RequestSelfUpdateStop(ctx, path, strings.Repeat("b", 32), 7); err != nil {
						t.Fatal(err)
					}
				case "missing-marker":
					if err := os.Remove(filepath.Join(path, ".control.lock")); err != nil {
						t.Fatal(err)
					}
				case "missing-current":
					if err := os.Remove(filepath.Join(path, "current-v1.json")); err != nil {
						t.Fatal(err)
					}
				case "bad-marker":
					if err := os.WriteFile(filepath.Join(path, ".control.lock"), []byte("unknown"), 0600); err != nil {
						t.Fatal(err)
					}
				case "unknown-current":
					if err := os.WriteFile(filepath.Join(path, "current-v1.json"), []byte("unknown"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := selfUpdateReadTree(t, base)
			var infos = map[string]os.FileInfo{}
			_ = filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
				if err == nil {
					infos[p] = info
				}
				return err
			})
			err := initializeCleanInstallControlLedger(ctx, gate, path)
			if err == nil || mode == "stopped" && !errors.Is(err, operationgate.ErrSelfUpdateStopped) ||
				!reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
				t.Fatal("retained owner was repaired/reset or accepted", err)
			}
			for p, info := range infos {
				after, err := os.Lstat(p)
				if err != nil || !os.SameFile(info, after) {
					t.Fatal("retained inode changed")
				}
			}
		})
	}
}

func TestCleanInstallControlLedgerRequiresOriginalOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control")
	ctx, gate := cleanInstallTestContext(t)
	other := &operationgate.Gate{}
	for _, test := range []struct {
		ctx  context.Context
		gate *operationgate.Gate
	}{{context.Background(), gate}, {nil, gate}, {ctx, other}, {ctx, nil}} {
		if initializeCleanInstallControlLedger(test.ctx, test.gate, path) == nil {
			t.Fatal("callerless/cross-gate initialization")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refused context created control")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if initializeCleanInstallControlLedger(canceled, gate, path) == nil {
		t.Fatal("canceled operation initialized")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("cancellation created control")
	}
}

func TestCleanInstallControlNonLinuxCannotUseEnvironmentAsIssuer(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux admission is a separate native cell")
	}
	base := t.TempDir()
	for _, key := range []string{"RAZVILKA_BASE", "RAZVILKA_CONFIG", "RAZVILKA_SELF_UPDATE_CONTROL_STATE", "RAZVILKA_SELF_UPDATE_INSTALLATION"} {
		t.Setenv(key, base)
	}
	before := selfUpdateReadTree(t, base)
	handled, code := runCommandWithSelfUpdateJournalRoots([]string{cleanInstallControlCommand, strings.Repeat("a", 64)}, productionSelfUpdateJournalRoots())
	if !handled || code != 3 || !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("environment supplied native issuer or created control", handled, code)
	}
}

func TestCleanInstallControlInstallerModelOverlayOnlyReplacesNativeLeaf(t *testing.T) {
	// This guards the mandatory temp-base test's truth boundary, not native
	// control initialization. Its sole substituted function must create no
	// ledger or installation authority; production code is built separately.
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "test-entware-transaction.sh"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "<<'CLEAN_CONTROL_MODEL'\n")
	if start < 0 {
		t.Fatal("missing isolated model leaf")
	}
	start += len("<<'CLEAN_CONTROL_MODEL'\n")
	end := strings.Index(source[start:], "\nCLEAN_CONTROL_MODEL\n")
	if end < 0 {
		t.Fatal("unbounded model leaf")
	}
	model := source[start : start+end]
	tree, err := parser.ParseFile(token.NewFileSet(), "model.go", model, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := 0
	for _, decl := range tree.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			functions++
			if fn.Name.Name != "initializeNativeCleanInstallControl" {
				t.Fatal("model replaced unrelated Main/owner behavior")
			}
		}
	}
	if functions != 1 || strings.Contains(model, "InitializeSelfUpdateControl") || strings.Contains(model, "ReadSelfUpdateStop") ||
		strings.Contains(model, "self-update-stop") || strings.Contains(source, "prepare_recorded_clean_bundle") ||
		strings.Contains(source, "CLEAN_CONTROL_MODEL_MAIN") {
		t.Fatal("model issued control or retained the old wrapper/handoff mechanism")
	}
	if !strings.Contains(source, `"$ROOT/cmd/razvilka/clean_install_control_linux.go"`) ||
		!strings.Contains(source, "{'Replace': {str(original.resolve()): str(modeled.resolve())}}") {
		t.Fatal("overlay no longer replaces exactly the dedicated native initializer leaf")
	}
}
