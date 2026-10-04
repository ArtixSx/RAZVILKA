//go:build linux

package strategylab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const (
	compatibilityTimerLibrary   = "-- Fixed Go lifecycle fixture: library data only; never evaluated.\n"
	compatibilityTimerAntidpi   = "-- Fixed Go lifecycle fixture: antidpi data only; never evaluated.\n"
	compatibilityTimerCandidate = "--filter-tcp=443 --lua-desync=fake:blob=0x00000000"
)

// This entry recognizes only one fixed dry-run timer shape. It never evaluates
// Lua, implements no NFQWS behavior and can never return a compatibility PASS.
// The 20-second watchdog bounds an orphan if a deliberately crashed helper
// leaves it alive. Ordinary test and fixed helper invocations still use m.Run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--dry-run" {
		if !compatibilityTimerArguments(os.Args[1:]) {
			os.Exit(92)
		}
		time.Sleep(20 * time.Second)
		os.Exit(93)
	}
	os.Exit(m.Run())
}

func compatibilityTimerArguments(args []string) bool {
	if len(args) != 6 || args[0] != "--dry-run" || args[1] != "--intercept=0" || args[4] != "--filter-tcp=443" || args[5] != "--lua-desync=fake:blob=0x00000000" {
		return false
	}
	for i, file := range []struct{ name, data string }{{"zapret-lib.lua", compatibilityTimerLibrary}, {"zapret-antidpi.lua", compatibilityTimerAntidpi}} {
		path, ok := strings.CutPrefix(args[i+2], "--lua-init=@")
		if !ok || !compatibilityCleanPath(path) || filepath.Base(path) != file.name {
			return false
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, []byte(file.data)) {
			return false
		}
	}
	return true
}

func TestNFQWSSupervisedHelperEntry(t *testing.T) {
	if len(os.Args) != 5 || os.Args[2] != "--" || os.Args[3] != "nfqws-compatibility-supervisor" {
		return
	}
	os.Exit(RunCompatibilitySupervisor(os.Args[4], os.Getenv("RAZVILKA_STRATEGY_LAB_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE")))
}

func TestNFQWSSupervisedCrashEntry(t *testing.T) {
	if len(os.Args) != 5 || os.Args[2] != "--" || os.Args[3] != "nfqws-compatibility-supervisor" || !compatibilityHex(os.Args[4], 32) {
		return
	}
	os.Exit(91)
}

// The local approval below authorizes only this fixed Go lifecycle fixture.
// Hashing these test bytes is never an installed NFQWS provenance decision.
func compatibilityControllerFixture(t *testing.T) (*Manager, *SupervisedCompatibilityProvider, CompatibilityApproval, Candidate) {
	t.Helper()
	if os.Getenv("RAZVILKA_NFQWS_PROCESS_FIXTURE") != "1" {
		t.Skip("root-only opt-in controller/process fixtures; no genuine NFQWS CLI/Lua")
	}
	dir := t.TempDir()
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := compatibilityProtectedPath(program, false); err != nil {
		t.Fatalf("compile this test executable into a protected private 0700 directory before running root fixtures: %v", err)
	}
	controlPath := filepath.Join(dir, "fixture-control")
	control, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(filepath.Join(dir, "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := m.AddCandidate("tcp-tls", "fixed Go timer fixture", compatibilityTimerCandidate, "expert")
	if err != nil {
		t.Fatal(err)
	}
	programData, err := os.ReadFile(program)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(programData)
	approval := CompatibilityApproval{BinaryPath: program, BinarySHA256: hex.EncodeToString(digest[:]), ControlPath: controlPath, InstallationID: control.InstallationID, Sequence: control.Sequence}
	for _, file := range []struct{ name, data string }{{"zapret-lib.lua", compatibilityTimerLibrary}, {"zapret-antidpi.lua", compatibilityTimerAntidpi}} {
		path := filepath.Join(dir, file.name)
		if err := os.WriteFile(path, []byte(file.data), 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(file.data))
		approval.BaseArguments = append(approval.BaseArguments, "--lua-init=@"+path)
		approval.Assets = append(approval.Assets, CompatibilityApprovedAsset{Path: path, SHA256: hex.EncodeToString(digest[:])})
	}
	p, err := NewSupervisedCompatibilityProvider(m, approval)
	if err != nil {
		t.Fatal(err)
	}
	p.helperPrefix = []string{"-test.run=^TestNFQWSSupervisedHelperEntry$", "--", "nfqws-compatibility-supervisor"}
	m.Validator = CompatibleValidator{Binary: program, BaseArguments: append([]string(nil), approval.BaseArguments...), TrustedAssets: true, Timeout: ProbeTimeout, Provider: p}
	return m, p, approval, candidate
}

func compatibilityControllerAssertUnknown(t *testing.T, m *Manager, p *SupervisedCompatibilityProvider, approval CompatibilityApproval, candidate Candidate) {
	t.Helper()
	image, err := restorejournal.ReadFileImage(context.Background(), m.Path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeCompatibilityState(image)
	if err != nil {
		t.Fatal(err)
	}
	active := compatibilityActiveInvocation(state.CompatibilitySession)
	if active == nil || active.Acknowledged || !compatibilitySessionUnknown(*state.CompatibilitySession) {
		t.Fatalf("unknown invocation acquired an accepted durable result: %+v", state.CompatibilitySession)
	}
	if active.Command.Phase != "dry-run" || state.CompatibilitySession.LuaInit != nil {
		t.Fatal("cancel/crash advanced into Lua-init")
	}
	if !m.Snapshot().QuiescenceUnknown {
		t.Fatal("live manager lost unknown fence")
	}
	if _, err := m.Validate(context.Background(), candidate.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("live replay allowed: %v", err)
	}
	completion, err := p.Run(context.Background(), approval.BinaryPath, append(append([]string{"--dry-run", "--intercept=0"}, approval.BaseArguments...), strings.Fields(compatibilityTimerCandidate)...)...)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || completion.Quiescent {
		t.Fatalf("provider replay allowed: %+v %v", completion, err)
	}
	reloaded, err := New(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Snapshot().QuiescenceUnknown {
		t.Fatal("reopen cleared unacknowledged session")
	}
	if _, err := NewSupervisedCompatibilityProvider(reloaded, approval); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("fresh provider bypassed retained unknown: %v", err)
	}
	if _, err := reloaded.Validate(context.Background(), candidate.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("reopened replay allowed: %v", err)
	}
}

func TestNFQWSSupervisedControllerCancellationRetainsUnknown(t *testing.T) {
	m, p, approval, candidate := compatibilityControllerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := m.Validate(ctx, candidate.ID)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || result.Validation.OK || result.Validation.Native || !result.Validation.QuiescenceUnknown {
		t.Fatalf("timer cancellation became accepted: %+v %v", result.Validation, err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("controller exceeded cancellation fixture bound: %s", elapsed)
	}
	compatibilityControllerAssertUnknown(t, m, p, approval, candidate)
}

func TestNFQWSSupervisedControllerHelperCrashRetainsUnknown(t *testing.T) {
	m, p, approval, candidate := compatibilityControllerFixture(t)
	p.helperPrefix = []string{"-test.run=^TestNFQWSSupervisedCrashEntry$", "--", "nfqws-compatibility-supervisor"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := m.Validate(ctx, candidate.ID)
	if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || result.Validation.OK || result.Validation.Native || !result.Validation.QuiescenceUnknown {
		t.Fatalf("helper crash became accepted: %+v %v", result.Validation, err)
	}
	compatibilityControllerAssertUnknown(t, m, p, approval, candidate)
}

func TestNFQWSSupervisedControllerStopAndForeignEpochBeforeIntent(t *testing.T) {
	for _, mode := range []string{"stopped", "foreign-sequence", "foreign-installation"} {
		t.Run(mode, func(t *testing.T) {
			m, p, approval, candidate := compatibilityControllerFixture(t)
			if mode == "stopped" {
				if _, err := operationgate.RequestSelfUpdateStop(context.Background(), approval.ControlPath, "0123456789abcdef0123456789abcdef", 1); err != nil {
					t.Fatal(err)
				}
			} else if mode == "foreign-sequence" {
				p.review.Sequence++
			} else {
				p.review.InstallationID = strings.Repeat("f", 32)
				if p.review.InstallationID == approval.InstallationID {
					p.review.InstallationID = strings.Repeat("e", 32)
				}
			}
			result, err := m.Validate(context.Background(), candidate.ID)
			if err != nil || result.Validation.OK || result.Validation.Native || result.Validation.QuiescenceUnknown || result.Validation.Code != "COMPATIBILITY_REJECTED" {
				t.Fatalf("pre-intent authority rejection changed outcome: %+v %v", result.Validation, err)
			}
			image, err := restorejournal.ReadFileImage(context.Background(), m.Path)
			if err != nil {
				t.Fatal(err)
			}
			var state State
			if err := json.Unmarshal(image.Data, &state); err != nil {
				t.Fatal(err)
			}
			if state.CompatibilitySession != nil || state.SchemaVersion != SchemaVersion || m.Snapshot().QuiescenceUnknown {
				t.Fatal("pre-intent refusal published a session/unknown fence")
			}
		})
	}
}
