package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func nfqws2ManagedRecordFixture(t *testing.T) (*NFQWS2Adapter, nfqws2ManagedProcessLease) {
	t.Helper()
	a, _, _ := newOwnedNFQWS2(t)
	if err := os.MkdirAll(a.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	owner, err := a.owner()
	if err != nil {
		t.Fatal(err)
	}
	command := nfqws2ManagedProcessCommand{
		ID: strings.Repeat("a", 32), StateRoot: a.StateRoot, Owner: owner,
		ControlRoot: filepath.Join(filepath.Dir(a.StateRoot), "control"), InstallationID: strings.Repeat("b", 32), Sequence: 1,
		Program: nfqws2ManagedFile{Path: filepath.Join(a.StateRoot, "fixture-program"), SHA256: strings.Repeat("c", 64)},
		Args:    []string{"--fixture-held-process"}, Parent: components.NFQWSSupervisionIdentity{BootID: "01234567-89ab-cdef-0123-456789abcdef", Start: "100", PID: 1000, Group: 1000}, Deadline: time.Unix(1800000000, 0).UTC(),
	}
	lease := nfqws2ManagedProcessLease{Version: 2, StateRoot: a.StateRoot, Owner: owner, Command: command, CommandSHA256: nfqws2ManagedCommandDigest(command), Receipt: components.NFQWSSupervisionReceipt{State: "intent"}}
	return a, lease
}

func nfqws2ManagedModelTerminal(lease nfqws2ManagedProcessLease) nfqws2ManagedProcessLease {
	lease.Receipt = components.NFQWSSupervisionReceipt{State: "reaped", BootID: lease.Command.Parent.BootID, Start: "200", PID: 2000, Group: 2000, ChildPID: 2001, CommandSHA256: lease.CommandSHA256, Started: true, DirectReaped: true, Reaped: 1, WaitECHILD: true}
	lease.Child = components.NFQWSRuntimeProcessIdentity{BootID: lease.Receipt.BootID, Start: "201", PID: 2001, Group: 2001, ParentPID: 2000, Executable: lease.Command.Program.Path, ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(lease.Command.Program.Path, lease.Command.Args)}
	lease.Acknowledged = true
	return lease
}

func TestNFQWSManagedProcessTerminalRequiresExactReceiptAndACK(t *testing.T) {
	for _, mode := range []string{"settled", "no-ack", "no-echild", "no-direct-reap", "no-reaped-child", "wrong-helper-birth", "wrong-helper-group", "wrong-boot", "wrong-command", "wrong-child-parent", "wrong-child-birth", "wrong-executable", "wrong-argv", "bad-cancel-exit", "negative-exit", "unknown-state"} {
		t.Run(mode, func(t *testing.T) {
			_, intent := nfqws2ManagedRecordFixture(t)
			lease := nfqws2ManagedModelTerminal(intent)
			switch mode {
			case "no-ack":
				lease.Acknowledged = false
			case "no-echild":
				lease.Receipt.WaitECHILD = false
			case "no-direct-reap":
				lease.Receipt.DirectReaped = false
			case "no-reaped-child":
				lease.Receipt.Reaped = 0
			case "wrong-helper-birth":
				lease.Receipt.Start = "0200"
			case "wrong-helper-group":
				lease.Receipt.Group++
			case "wrong-boot":
				lease.Receipt.BootID = "11234567-89ab-cdef-0123-456789abcdef"
			case "wrong-command":
				lease.Receipt.CommandSHA256 = strings.Repeat("d", 64)
			case "wrong-child-parent":
				lease.Child.ParentPID++
			case "wrong-child-birth":
				lease.Child.Start = "0201"
			case "wrong-executable":
				lease.Child.Executable += "-other"
			case "wrong-argv":
				lease.Child.ArgumentsSHA256 = strings.Repeat("e", 64)
			case "bad-cancel-exit":
				lease.Receipt.Cancelled = true
			case "negative-exit":
				lease.Receipt.ExitCode = -1
			case "unknown-state":
				lease.Receipt.State = "unknown"
			}
			if settled := nfqws2ManagedProcessSettled(lease); settled != (mode == "settled") {
				t.Fatal("unowned/ambiguous process acquired settled proof", settled)
			}
		})
	}
}

func TestNFQWSManagedPendingAndCancelledReceipts(t *testing.T) {
	_, intent := nfqws2ManagedRecordFixture(t)
	if nfqws2ValidateManagedLease(intent) != nil || nfqws2ManagedProcessSettled(intent) {
		t.Fatal("intent was invalid or became inactivity proof")
	}
	terminal := nfqws2ManagedModelTerminal(intent)
	terminal.Receipt.Cancelled, terminal.Receipt.ExitCode = true, 125
	if !nfqws2ManagedProcessSettled(terminal) {
		t.Fatal("exact cancelled ECHILD receipt lost process-only settlement")
	}
	for _, state := range []string{"armed", "running"} {
		lease := terminal
		lease.Acknowledged = false
		lease.Receipt.State, lease.Receipt.WaitECHILD, lease.Receipt.DirectReaped = state, false, false
		lease.Receipt.Reaped, lease.Receipt.ExitCode, lease.Receipt.Cancelled = 0, 0, false
		if state == "armed" {
			lease.Receipt.Started, lease.Receipt.ChildPID, lease.Child = false, 0, components.NFQWSRuntimeProcessIdentity{}
		}
		if nfqws2ValidateManagedLease(lease) != nil || nfqws2ManagedProcessSettled(lease) {
			t.Fatal("pending phase became proof", state)
		}
	}
	terminal.Receipt.State, terminal.Receipt.Started, terminal.Receipt.ChildPID, terminal.Receipt.DirectReaped, terminal.Receipt.Reaped = "not-started", false, 0, false, 0
	terminal.Child = components.NFQWSRuntimeProcessIdentity{}
	if !nfqws2ManagedProcessSettled(terminal) {
		t.Fatal("exact not-started ECHILD proof was rejected")
	}
}

func TestNFQWSManagedRecordRejectsAmbiguousAndForeignJSON(t *testing.T) {
	a, lease := nfqws2ManagedRecordFixture(t)
	image, err := nfqws2ManagedLeaseImage(nfqws2ManagedModelTerminal(lease))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "duplicate", "case-alias", "unicode-alias", "unknown", "trailing", "invalid-utf8", "legacy", "other-root", "other-owner"} {
		t.Run(mode, func(t *testing.T) {
			data := append([]byte(nil), image.Data...)
			root, owner := a.StateRoot, lease.Owner
			switch mode {
			case "duplicate":
				data = bytes.Replace(data, []byte(`"version": 2`), []byte(`"version": 2, "version": 2`), 1)
			case "case-alias":
				data = bytes.Replace(data, []byte(`"version": 2`), []byte(`"version": 2, "VERSION": 2`), 1)
			case "unicode-alias":
				data = bytes.Replace(data, []byte(`"version": 2`), []byte(`"version": 2, "ver\u017fion": 2`), 1)
			case "unknown":
				data = bytes.Replace(data, []byte(`"version": 2`), []byte(`"version": 2, "ready": true`), 1)
			case "trailing":
				data = append(data, []byte(`{}`)...)
			case "invalid-utf8":
				data = append(data, 0xff)
			case "legacy":
				data = []byte(`{"version":1}`)
			case "other-root":
				root += "-other"
			case "other-owner":
				owner = strings.Repeat("f", 24)
			}
			_, err := nfqws2DecodeManagedLease(restorejournal.Image{Exists: true, Data: data}, root, owner)
			if (err == nil) != (mode == "valid") {
				t.Fatal("ambiguous or foreign lifecycle was adopted", err)
			}
		})
	}
}

func TestNFQWSManagedSharedWriterRefusesLegacyErase(t *testing.T) {
	a, lease := nfqws2ManagedRecordFixture(t)
	path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	store := nfqws2ManagedProcessStore{target: target, lease: lease}
	t.Cleanup(store.close)
	if err := store.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), store.image.Data...)
	for _, held := range []bool{true, false} {
		if !held {
			store.close()
		}
		if err := a.writeLease(nil); err == nil {
			t.Fatal("legacy writer erased managed lifecycle", held)
		}
		if err := a.Deactivate(context.Background()); err == nil {
			t.Fatal("legacy package cleanup accepted managed lifecycle", held)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, actual) {
			t.Fatal("managed receipt image changed on refused cleanup", err)
		}
	}
}

func TestNFQWSManagedStoreCASPreservesForeignImage(t *testing.T) {
	a, lease := nfqws2ManagedRecordFixture(t)
	path := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	target, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	store := nfqws2ManagedProcessStore{target: target, lease: lease}
	if err := store.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreign := []byte(`{"foreign":true}`)
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	store.lease = nfqws2ManagedModelTerminal(lease)
	if err := store.publish(context.Background()); !errors.Is(err, ErrNFQWSManagedProcessUnknown) || !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("changed authority was overwritten or treated as settled", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, foreign) {
		t.Fatal("foreign authority image changed", err)
	}
}

func TestNFQWSManagedInactivityRefusesMissingLegacyAndCancelled(t *testing.T) {
	a, _, root := newOwnedNFQWS2(t)
	if err := a.VerifyRuntimeInactive(context.Background()); err == nil {
		t.Fatal("missing ownership became inactivity proof")
	}
	transaction := stageOwnedNFQWS2(t, a, root, "legacy.example")
	if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	before := readNFQWS2Files(t, a)
	if err := a.VerifyRuntimeInactive(context.Background()); err == nil {
		t.Fatal("legacy file-only ownership became process/kernel proof")
	}
	assertNFQWS2Files(t, a, before)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.VerifyRuntimeInactive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled observer acquired proof", err)
	}
}
