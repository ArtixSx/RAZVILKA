package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const pairedRestoreCommandID = "0123456789abcdef0123456789abcdef"

func pairedRestoreOwnerFixture(t *testing.T) (*pairedRestoreOwner, context.Context, func()) {
	t.Helper()
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	var gate operationgate.Gate
	ctx, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	path := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, path, pairedRestoreCommandID, 9); err != nil {
		t.Fatal(err)
	}
	owner, err := openPairedRestoreOwner(ctx, &gate, path, pairedRestoreCommandID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.close)
	return owner, ctx, release
}

func TestPairedRestoreCommandOwnerUsesExistingStoppedEpochWithoutClearingIt(t *testing.T) {
	owner, ctx, _ := pairedRestoreOwnerFixture(t)
	before := owner.stop
	calls := 0
	if err := owner.admit(ctx, pairedRestoreCommandID, "paired-offline-file-0", func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	after, present, err := operationgate.ReadSelfUpdateStop(ctx, owner.path)
	if err != nil || !present || after != before || !after.Stopped {
		t.Fatal("offline admission cleared/rewound Stop", err)
	}
	for _, effect := range []string{"start-candidate-panel", "paired-offline-file--1", "paired-offline-file-+1", "paired-offline-file-01", "paired-offline-file-40000", "paired-offline-file-"} {
		if err := owner.admit(ctx, pairedRestoreCommandID, effect, func() error { calls++; return nil }); err == nil || calls != 1 {
			t.Fatal("foreign effect admitted", effect, err, calls)
		}
	}
}

func TestPairedRestoreCommandOwnerRefusesDTOReleasedOrDifferentOriginalOwner(t *testing.T) {
	owner, ctx, release := pairedRestoreOwnerFixture(t)
	if owner.current(context.Background(), pairedRestoreCommandID) == nil || owner.current(context.WithValue(ctx, "child", true), pairedRestoreCommandID) == nil || owner.current(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == nil {
		t.Fatal("detached context/transaction accepted")
	}
	bare := &pairedRestoreOwner{ctx: ctx, id: pairedRestoreCommandID, stop: owner.stop}
	if bare.current(ctx, pairedRestoreCommandID) == nil {
		t.Fatal("observed Stop DTO manufactured authority")
	}
	var foreign operationgate.Gate
	original := owner.gate
	owner.gate = &foreign
	if owner.current(ctx, pairedRestoreCommandID) == nil {
		t.Fatal("different Gate accepted original context")
	}
	owner.gate = original
	release()
	if owner.current(ctx, pairedRestoreCommandID) == nil {
		t.Fatal("released original owner accepted")
	}
}

func TestPairedRestoreCommandOwnerRefusesProtectedMarkerOrRootRebinding(t *testing.T) {
	for _, target := range []string{"root", "marker"} {
		t.Run(target, func(t *testing.T) {
			owner, ctx, _ := pairedRestoreOwnerFixture(t)
			path := owner.path
			if target == "marker" {
				path = filepath.Join(path, ".control.lock")
			}
			if err := os.Rename(path, path+".retained"); err != nil {
				// A Windows held handle can deny the move itself. Native Linux
				// exercises the successful rebind and pinned-inode refusal.
				return
			}
			if target == "root" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("foreign marker"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			if err := owner.admit(ctx, pairedRestoreCommandID, "paired-offline-file-0", func() error { calls++; return nil }); err == nil || calls != 0 {
				t.Fatal("rebound protected incarnation admitted", err, calls)
			}
		})
	}
}

func TestPairedRestoreCommandRejectsUnscopedOwnerAndMalformedArguments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var gate operationgate.Gate
	if _, err := openPairedRestoreOwner(ctx, &gate, filepath.Join(t.TempDir(), "missing"), pairedRestoreCommandID); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("unscoped context touched control roots", err)
	}
	for _, args := range [][]string{{"self-update-paired-restore"}, {"self-update-paired-restore", "../foreign"}, {"self-update-paired-restore", pairedRestoreCommandID, "--root", "foreign"}} {
		if handled, code := runPairedRestoreCommand(args, productionSelfUpdateJournalRoots()); !handled || code != 2 {
			t.Fatal("malformed restore routed to startup", args, handled, code)
		}
	}
}
