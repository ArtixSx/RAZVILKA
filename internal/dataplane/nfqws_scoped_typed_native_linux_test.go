//go:build linux && (amd64 || arm64)

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// ROOT opts into one actual provider and its own exact reviewed NFQWS process.
// This narrow test changes no rules/links/LAN/sysctls and adopts no live PID.
// It needs a positively readable empty queue inventory before any Start.
func TestNFQWSScopedTypedQueueNative(t *testing.T) {
	mode := os.Getenv("RAZVILKA_NFQWS_TYPED_QUEUE_NATIVE")
	if mode == "" {
		t.Skip("ROOT typed queue opt-in disabled")
	}
	if mode != "proc" && mode != "stock-nc1812" || os.Geteuid() != 0 {
		t.Fatal("typed queue native: stage=PROFILE outcome=unknown capability=ungranted")
	}
	nfqws2ManagedNativeGate(t)
	setup, stopSetup := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopSetup()
	provider := netidentity.NewProcProvider()
	var err error
	if mode == "stock-nc1812" {
		provider, err = netidentity.NewReviewedStockNC1812Provider(setup)
		if err != nil {
			t.Fatal("typed queue native: stage=PROVIDER outcome=unknown capability=ungranted")
		}
	}
	expected, err := provider.Observe(setup)
	if err != nil {
		t.Fatal("typed queue native: stage=IDENTITY outcome=unknown capability=ungranted")
	}
	const queue = uint16(40321)
	checkEmpty := func(stage string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if CheckTypedNFQWSScopedQueue(ctx, provider, expected, queue, nil) != nil {
			t.Fatalf("typed queue native: stage=%s outcome=unknown capability=ungranted", stage)
		}
	}
	checkEmpty("OPENING_EMPTY")
	// Even a currently empty queue can have preexisting capture targets.
	// Refuse those before binding a test process into the live namespace.
	profileMode := "linux70"
	if mode == "stock-nc1812" {
		profileMode = mode
	}
	profile, err := backendNativeFixtureProfile(profileMode)
	if err != nil {
		t.Fatal("typed queue native: stage=TOOLS_PROFILE outcome=unknown capability=ungranted")
	}
	toolsCtx, cancelTools := context.WithTimeout(context.Background(), 2*time.Second)
	held, err := backendNativeHeldTools(toolsCtx, profile)
	cancelTools()
	if err != nil {
		t.Fatalf("typed queue native: stage=TOOLS tool-step=%s outcome=unknown capability=ungranted", backendNativeTrace(err))
	}
	defer func() {
		if held.close() != nil {
			t.Error("typed queue native: stage=TOOLS_CLOSE outcome=unknown capability=ungranted")
		}
	}()
	tools := BackendInventoryTools{Runner: nfqws2ExecRunner{}, IPTables: profile.aliases[0], IP6Tables: profile.aliases[1], ReviewSHA256: profile.mainSHA, Check: held.check}
	inventory, err := NewBackendInventory(provider, tools)
	if mode == "stock-nc1812" {
		inventory, err = NewReviewedStockNC1812BackendInventory(provider, tools)
	}
	if err != nil {
		t.Fatal("typed queue native: stage=INVENTORY_CONSTRUCTOR outcome=unknown capability=ungranted")
	}
	checkNoCapture := func(stage string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		snapshot, err := inventory.Read(ctx, expected)
		if err != nil || snapshot.RequireComplete() != nil {
			t.Fatalf("typed queue native: stage=%s outcome=unknown capability=ungranted", stage)
		}
		for _, row := range snapshot.Rows {
			for i := 2; i+1 < len(row.Tokens); i++ {
				if (row.Tokens[i] == "-j" || row.Tokens[i] == "-g") && (row.Tokens[i+1] == "NFQUEUE" || row.Tokens[i+1] == "QUEUE") {
					t.Fatalf("typed queue native: stage=%s outcome=foreign-capture capability=ungranted", stage)
				}
			}
		}
	}
	checkNoCapture("OPENING_CAPTURE_ABSENCE")
	var review struct {
		BinaryPath, BinarySHA256 string
		Assets                   []nfqws2ManagedFile
		BaseArguments            []string
	}
	input := os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW")
	reviewFile, err := os.Open(input)
	if input == "" || err != nil {
		t.Fatal("typed queue native: stage=REVIEW_OPEN outcome=unknown capability=ungranted")
	}
	data, readErr := io.ReadAll(io.LimitReader(reviewFile, (64<<10)+1))
	closeErr := reviewFile.Close()
	if readErr != nil || closeErr != nil || len(data) > 64<<10 || nfqws2ManagedUniqueJSON(data) != nil ||
		json.Unmarshal(data, &review) != nil || len(review.Assets) > 16 || len(review.BaseArguments) == 0 || len(review.BaseArguments) > 32 {
		t.Fatal("typed queue native: stage=REVIEW outcome=unknown capability=ungranted")
	}
	for _, arg := range review.BaseArguments {
		if !strings.HasPrefix(arg, "--lua-init=@") && !strings.HasPrefix(arg, "--blob=") {
			t.Fatal("typed queue native: stage=REVIEW_ARGUMENTS outcome=unknown capability=ungranted")
		}
	}
	private, err := os.MkdirTemp("", "razvilka-typed-queue-")
	if err != nil {
		t.Fatal("typed queue native: stage=PRIVATE_ROOT outcome=unknown capability=ungranted")
	}
	safeCleanup := false
	defer func() {
		if safeCleanup {
			if os.RemoveAll(private) != nil {
				t.Error("typed queue native: stage=PRIVATE_CLEANUP outcome=unknown capability=ungranted")
			}
		} else {
			t.Log("typed queue native: retained-private-fixture=true capability=ungranted")
		}
	}()
	a := &NFQWS2Adapter{StateRoot: filepath.Join(private, "dataplane", "runtime", "nfqws2")}
	if os.MkdirAll(a.StateRoot, 0700) != nil {
		t.Fatal("typed queue native: stage=STATE_ROOT outcome=unknown capability=ungranted")
	}
	controlRoot := filepath.Join(private, "self-update-control")
	controlCtx, cancelControl := context.WithTimeout(context.Background(), 2*time.Second)
	_, err = operationgate.InitializeSelfUpdateControl(controlCtx, controlRoot)
	cancelControl()
	if err != nil {
		t.Fatal("typed queue native: stage=CONTROL_SETUP outcome=unknown capability=ungranted")
	}
	command := nfqws2ManagedNativeCommand(t, a, controlRoot, review.BinaryPath, review.BinarySHA256, strings.Repeat("5", 32), "hold")
	command.Program, command.Assets = nfqws2ManagedFile{review.BinaryPath, review.BinarySHA256}, review.Assets
	command.Args = append([]string{"--intercept=1", "--qnum=40321"}, review.BaseArguments...)
	command.Args = append(command.Args, "--filter-udp=443", "--lua-desync=fake:blob=0x00000000")
	command.Deadline = time.Now().Add(15 * time.Second).UTC()
	checkNoCapture("PRE_START_CAPTURE_ABSENCE")
	checkEmpty("PRE_START_EMPTY")
	request, stop := context.WithDeadline(context.Background(), command.Deadline)
	type result struct {
		lease nfqws2ManagedProcessLease
		err   error
	}
	done := make(chan result, 1)
	go func() {
		lease, err := a.runManagedNFQWSProcess(request, command, []string{"-test.run=^TestNFQWSManagedProcessNativeEntry$", "nfqws-managed-helper"})
		done <- result{lease, err}
	}()
	joined := false
	defer func() {
		stop()
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("typed queue native: stage=EXCEPTIONAL_JOIN outcome=unknown capability=ungranted")
			}
		}
	}()
	owner, err := a.owner()
	if err != nil {
		t.Fatal("typed queue native: stage=OWNER outcome=unknown capability=ungranted")
	}
	start := time.Now()
	ready := false
	for !ready {
		if time.Since(start) >= 8*time.Second {
			t.Fatal("typed queue native: stage=READINESS_DEADLINE outcome=unknown capability=ungranted")
		}
		ctx, cancel := context.WithTimeout(request, 2*time.Second)
		image, readErr := restorejournal.ReadFileImage(ctx, filepath.Join(a.StateRoot, nfqws2LeaseFile))
		if readErr != nil {
			cancel()
			t.Fatal("typed queue native: stage=LEASE_READ outcome=unknown capability=ungranted")
		}
		lease, decodeErr := nfqws2DecodeManagedLease(image, a.StateRoot, owner)
		if image.Exists && (decodeErr != nil || !reflect.DeepEqual(lease.Command, command) || lease.LaunchBinding != nil) {
			cancel()
			t.Fatal("typed queue native: stage=LEASE_BINDING outcome=unknown capability=ungranted")
		}
		if readErr == nil && decodeErr == nil && lease.Receipt.State == "running" && lease.Child.PID > 1 {
			ready, err = nfqwsScopedTypedQueueReadiness(ctx, provider, expected, queue, &lease.Child)
			if err == nil && ready {
				err = CheckTypedNFQWSScopedQueue(ctx, provider, expected, queue, &lease.Child)
			}
			cancel()
			if err != nil {
				t.Fatal("typed queue native: stage=OWNED_READBACK outcome=unknown capability=ungranted")
			}
		} else {
			cancel()
			if image.Exists && (decodeErr != nil || lease.Receipt.State == "reaped" || lease.Receipt.State == "not-started") {
				t.Fatal("typed queue native: stage=PROCESS_READBACK outcome=unknown capability=ungranted")
			}
		}
		if !ready {
			select {
			case <-request.Done():
				t.Fatal("typed queue native: stage=ORIGINAL_CANCEL outcome=unknown capability=ungranted")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	stop()
	select {
	case terminal := <-done:
		joined = true
		if !errors.Is(terminal.err, context.Canceled) || !nfqws2ManagedProcessSettled(terminal.lease) ||
			!terminal.lease.Receipt.DirectReaped || !terminal.lease.Receipt.WaitECHILD || !terminal.lease.Acknowledged ||
			!terminal.lease.Receipt.Cancelled || terminal.lease.Receipt.ExitCode != 125 {
			t.Fatal("typed queue native: stage=STOP_ECHILD_ACK outcome=unknown capability=ungranted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("typed queue native: stage=STOP_JOIN outcome=unknown capability=ungranted")
	}
	checkEmpty("CLOSING_EMPTY")
	checkNoCapture("CLOSING_CAPTURE_ABSENCE")
	safeCleanup = true
	t.Logf("typed queue native: mode=%s opening-empty=true exact-child-owned=true stop-echild=true parent-ack=true closing-empty=true elapsed-ms=%d rules-mutated=false capability=ungranted", mode, time.Since(start).Milliseconds())
}
