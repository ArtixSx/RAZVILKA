//go:build linux && (amd64 || arm64)

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func nfqws2ActiveNativeTrace(err error) string {
	var stages []string
	var visit func(error, int)
	visit = func(e error, depth int) {
		if e == nil || depth > 16 || len(stages) >= 16 {
			return
		}
		if d, ok := e.(*nfqws2ActiveDiagnostic); ok {
			stages = append(stages, d.stage)
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range u.Unwrap() {
				visit(child, depth+1)
			}
		case interface{ Unwrap() error }:
			visit(u.Unwrap(), depth+1)
		}
	}
	visit(err, 0)
	if errors.Is(err, context.DeadlineExceeded) {
		stages = append(stages, "DEADLINE")
	}
	if errors.Is(err, context.Canceled) {
		stages = append(stages, "CANCELLED")
	}
	if len(stages) == 0 {
		return "UNKNOWN"
	}
	return strings.Join(stages, "/") // Only static internal stage labels, never Error/payload.
}

// Explicit ROOT-owned genuine-process fixture. The callback models below
// test the process protocol only; they are never production Manager/CORE
// issuers and make no claim about common A-E records, config CAS or LAN effects.
func TestNFQWSActiveProcessNative(t *testing.T) {
	mode := os.Getenv("RAZVILKA_NFQWS_ACTIVE_NATIVE")
	if mode == "" {
		t.Skip("ROOT genuine active process opt-in disabled")
	}
	if mode != "proc" && mode != "stock-nc1812" || os.Geteuid() != 0 {
		t.Fatal("active native: stage=PROFILE outcome=unknown capability=ungranted")
	}
	nfqws2ManagedNativeGate(t)
	for _, scenario := range []string{"request-end-and-expiry", "prepared-cancel", "panel-stop"} {
		t.Run(scenario, func(t *testing.T) { nfqws2ActiveProcessNativeScenario(t, mode, scenario) })
	}
}

func nfqws2ActiveProcessNativeScenario(t *testing.T, mode, scenario string) {
	t.Helper()
	setup, finishSetup := context.WithTimeout(context.Background(), 2*time.Second)
	defer finishSetup()
	provider := netidentity.NewProcProvider()
	var err error
	if mode == "stock-nc1812" {
		provider, err = netidentity.NewReviewedStockNC1812Provider(setup)
		if err != nil {
			t.Fatal("active native: stage=PROVIDER outcome=unknown")
		}
	}
	identity, err := provider.Observe(setup)
	if err != nil {
		t.Fatal("active native: stage=IDENTITY outcome=unknown")
	}
	profileMode := "linux70"
	if mode == "stock-nc1812" {
		profileMode = mode
	}
	profile, err := backendNativeFixtureProfile(profileMode)
	if err != nil {
		t.Fatal("active native: stage=TOOLS_PROFILE outcome=unknown")
	}
	toolsCtx, finishTools := context.WithTimeout(context.Background(), 2*time.Second)
	held, err := backendNativeHeldTools(toolsCtx, profile)
	finishTools()
	if err != nil {
		t.Fatalf("active native: stage=TOOLS tool-step=%s outcome=unknown", backendNativeTrace(err))
	}
	defer func() {
		if held.close() != nil {
			t.Error("active native: stage=TOOLS_CLOSE outcome=unknown")
		}
	}()
	tools := BackendInventoryTools{Runner: nfqws2ExecRunner{}, IPTables: profile.aliases[0], IP6Tables: profile.aliases[1], ReviewSHA256: profile.mainSHA, Check: held.check}
	inventory, err := NewBackendInventory(provider, tools)
	if mode == "stock-nc1812" {
		inventory, err = NewReviewedStockNC1812BackendInventory(provider, tools)
	}
	if err != nil {
		t.Fatal("active native: stage=COLLECTOR outcome=unknown")
	}
	noCapture := func(ctx context.Context) error {
		snapshot, err := inventory.Read(ctx, identity)
		if err != nil || snapshot.RequireComplete() != nil {
			return ErrNFQWSScopedOwner
		}
		for _, row := range snapshot.Rows {
			for i := 2; i+1 < len(row.Tokens); i++ {
				if (row.Tokens[i] == "-j" || row.Tokens[i] == "-g") && (row.Tokens[i+1] == "NFQUEUE" || row.Tokens[i+1] == "QUEUE") {
					return ErrNFQWSScopedOwner
				}
			}
		}
		return ctx.Err()
	}
	empty := func(ctx context.Context) error {
		return CheckTypedNFQWSScopedQueue(ctx, provider, identity, 40321, nil)
	}
	checkClosing := func(stage string) {
		t.Helper()
		ctx, finish := context.WithTimeout(context.Background(), 6*time.Second)
		defer finish()
		if empty(ctx) != nil || noCapture(ctx) != nil {
			t.Fatalf("active native: stage=%s outcome=unknown", stage)
		}
	}
	checkClosing("OPENING_EMPTY_CAPTURE_ABSENCE")
	var review struct {
		BinaryPath, BinarySHA256 string
		Assets                   []nfqws2ManagedFile
		BaseArguments            []string
	}
	file, err := os.Open(os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW"))
	if err != nil {
		t.Fatal("active native: stage=REVIEW_OPEN outcome=unknown")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 64<<10 || nfqws2ManagedUniqueJSON(data) != nil || json.Unmarshal(data, &review) != nil || len(review.Assets) > 16 || len(review.BaseArguments) == 0 || len(review.BaseArguments) > 32 {
		t.Fatal("active native: stage=REVIEW outcome=unknown")
	}
	for _, arg := range review.BaseArguments {
		if !strings.HasPrefix(arg, "--lua-init=@") && !strings.HasPrefix(arg, "--blob=") {
			t.Fatal("active native: stage=REVIEW_ARGUMENTS outcome=unknown")
		}
	}
	private, err := os.MkdirTemp("", "razvilka-active-nfq-")
	if err != nil {
		t.Fatal("active native: stage=PRIVATE_ROOT outcome=unknown")
	}
	safeCleanup := false
	defer func() {
		if safeCleanup {
			if os.RemoveAll(private) != nil {
				t.Error("active native: stage=PRIVATE_CLEANUP outcome=unknown")
			}
		} else {
			t.Log("active native: retained-private-fixture=true capability=ungranted")
		}
	}()
	a := &NFQWS2Adapter{StateRoot: filepath.Join(private, "dataplane", "runtime", "nfqws2")}
	if os.MkdirAll(a.StateRoot, 0700) != nil {
		t.Fatal("active native: stage=STATE_ROOT outcome=unknown")
	}
	control := filepath.Join(private, "self-update-control")
	controlCtx, finishControl := context.WithTimeout(context.Background(), 2*time.Second)
	_, err = operationgate.InitializeSelfUpdateControl(controlCtx, control)
	finishControl()
	if err != nil {
		t.Fatal("active native: stage=CONTROL outcome=unknown")
	}
	old := nfqws2ManagedNativeCommand(t, a, control, review.BinaryPath, review.BinarySHA256, strings.Repeat("6", 32), "hold")
	c := nfqws2ActiveProcessCommand{Version: 1, Mode: nfqws2ActiveProcessMode, ID: old.ID, StateRoot: old.StateRoot, Owner: old.Owner, ControlRoot: control, InstallationID: old.InstallationID, Sequence: old.Sequence, Program: nfqws2ManagedFile{Path: review.BinaryPath, SHA256: review.BinarySHA256}, Assets: review.Assets, Parent: old.Parent, NetworkIdentity: identity, ActivationDeadline: time.Now().Add(15 * time.Second).UTC()}
	c.Args = append([]string{"--intercept=1", "--qnum=40321"}, review.BaseArguments...)
	c.Args = append(c.Args, "--filter-udp=443", "--lua-desync=fake:blob=0x00000000")
	spec := NFQWSScopedSpec{Queue: 40321, BootID: identity.BootID, SessionID: c.ID, CommandSHA256: nfqws2ActiveCommandDigest(c), NetworkIdentity: &identity,
		Candidate: NFQWSScopedCandidate{ID: "active-native", Incarnation: strings.Repeat("7", 32), ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(c.Program.Path, c.Args), Traffic: []NFQWSScopedTraffic{{Protocol: "udp", First: 443, Last: 443}}}}
	if identity.Kind == netidentity.ProcNetInode {
		spec.NetNamespace = fmt.Sprintf("net:[%d]", identity.Inode)
	}
	binding := NFQWSExecutionBinding{ExecutionID: "dp-1123456789abcdef", PlanID: "dp-0123456789abcdef", PlanDigest: strings.Repeat("b", 64), ResourceID: "nq-" + strings.Repeat("c", 32), ResourceGeneration: strings.Repeat("d", 64), EffectsDigest: strings.Repeat("e", 64), SessionID: c.ID, CommandSHA256: spec.CommandSHA256}
	request, cancelRequest := context.WithDeadline(context.Background(), c.ActivationDeadline)
	defer cancelRequest()
	panel, cancelPanel := context.WithCancel(context.Background())
	defer cancelPanel()
	var prepared *NFQWSPreparedHandle
	var active *NFQWSActiveHandle
	defer func() {
		ctx, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if !safeCleanup {
			if active != nil {
				_, _ = active.Stop(ctx)
			} else if prepared != nil {
				_, _ = prepared.Stop(ctx)
			}
		}
	}()
	current := func(ctx context.Context, actual NFQWSExecutionBinding) error {
		if actual != binding || ctx.Err() != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		return nfqws2ManagedControlCurrent(ctx, c.fileShape())
	}
	published := 0
	admission := nfqws2ActiveProcessAdmission{Binding: binding, Spec: spec, Provider: provider, Current: current,
		BeforeStart: func(ctx context.Context, actual NFQWSExecutionBinding) error {
			if current(ctx, actual) != nil || empty(ctx) != nil {
				return ErrNFQWSScopedOwner
			}
			return noCapture(ctx)
		},
		WithStart: func(ctx context.Context, actual NFQWSExecutionBinding, begin func() error) error {
			if err := current(ctx, actual); err != nil {
				return err
			}
			return begin()
		},
		Prepared: func(ctx context.Context, actual NFQWSExecutionBinding, obs NFQWSActiveObservation) error {
			p := nfqws2ActivePreparedFromContext(ctx)
			if p == nil || current(ctx, actual) != nil || p.VerifyOwnerObservation(ctx, obs) != nil {
				return ErrNFQWSScopedOwner
			}
			if err := noCapture(ctx); err != nil {
				return err
			}
			return p.VerifyOwnerObservation(ctx, obs)
		},
		WithTransfer: func(ctx context.Context, actual NFQWSExecutionBinding, finish func() error) error {
			if err := current(ctx, actual); err != nil {
				return err
			}
			return finish()
		},
		PublishTransferACK: func(ctx context.Context, obs NFQWSActiveObservation) error {
			if published != 0 || obs.Binding != binding || prepared == nil || prepared.VerifyOwnerObservation(ctx, obs) != nil {
				return ErrNFQWSScopedOwner
			}
			published++
			return nil
		},
	}
	start := time.Now()
	prepared, err = a.startPreparedNFQWSProcess(request, panel, c, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"}, admission)
	if err != nil || prepared == nil {
		t.Fatalf("active native: stage=START_PREPARED owner-step=%s elapsed-ms=%d outcome=unknown", nfqws2ActiveNativeTrace(err), time.Since(start).Milliseconds())
	}
	if scenario == "prepared-cancel" {
		cancelRequest()
		ctx, finish := context.WithTimeout(context.Background(), 5*time.Second)
		proof, err := prepared.Stop(ctx)
		finish()
		if err != nil || !proof.Acknowledged || !proof.Receipt.WaitECHILD || !proof.Receipt.DirectReaped || !proof.Receipt.Cancelled || proof.Receipt.ExitCode != 125 {
			t.Fatal("active native: stage=PRECOMMIT_ABORT_ECHILD_ACK outcome=unknown")
		}
	} else {
		committed := func(ctx context.Context, h *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			if obs.Binding != binding {
				return ErrNFQWSScopedOwner
			}
			return h.VerifyOwnerObservation(ctx, obs)
		}
		cleanup := func(ctx context.Context, h *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			if obs.Binding != binding {
				return ErrNFQWSScopedOwner
			}
			return h.VerifyCleanupObservation(ctx, obs)
		}
		active, err = prepared.CommitPrepared(request, committed, cleanup)
		if err != nil || active == nil || published != 1 {
			t.Fatalf("active native: stage=FINAL_ACK_COMMIT owner-step=%s elapsed-ms=%d outcome=unknown", nfqws2ActiveNativeTrace(err), time.Since(start).Milliseconds())
		}
		if scenario == "request-end-and-expiry" {
			cancelRequest()
			ctx, finish := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = active.Current(ctx)
			finish()
			if err != nil {
				t.Fatal("active native: stage=REQUEST_END_CURRENT outcome=unknown")
			}
			// Actual command metadata deadline expires while the genuine child
			// remains attached to its panel owner; no deadline is extended.
			remaining := time.Until(c.ActivationDeadline) + 150*time.Millisecond
			if remaining > 0 {
				time.Sleep(remaining)
			}
			ctx, finish = context.WithTimeout(context.Background(), 5*time.Second)
			_, err = active.Current(ctx)
			finish()
			if err != nil {
				t.Fatal("active native: stage=EXPIRED_ACTIVATION_STILL_ACTIVE outcome=unknown")
			}
		} else {
			cancelPanel()
		}
		ctx, finish := context.WithTimeout(context.Background(), 5*time.Second)
		proof, err := active.Stop(ctx)
		finish()
		if err != nil || !proof.Acknowledged || !proof.Receipt.WaitECHILD || !proof.Receipt.DirectReaped || !proof.Receipt.Cancelled || proof.Receipt.ExitCode != 125 {
			t.Fatal("active native: stage=STOP_ECHILD_ACK outcome=unknown")
		}
	}
	checkClosing("CLOSING_EMPTY_CAPTURE_ABSENCE")
	safeCleanup = true
	t.Logf("active native: mode=%s scenario=%s genuine-child=true sole-join-echild=true parent-ack=true closing-empty=true elapsed-ms=%d rules-mutated=false common-journals-tested=false capability=ungranted", mode, scenario, time.Since(start).Milliseconds())
}
