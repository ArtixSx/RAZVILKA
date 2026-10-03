package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func nodeAdmissionFixture(t *testing.T) *NodeHistoryAdmission {
	t.Helper()
	configRoot, stateRoot, installation := t.TempDir(), t.TempDir(), t.TempDir()
	executable := filepath.Join(installation, "controller")
	retainedFile(t, installation, "controller", []byte("trusted-current-controller"))
	retainedFile(t, configRoot, "nodes-private/nodes.private.json", retainedNodeFixture(t, false))
	return &NodeHistoryAdmission{configRoot: configRoot, stateRoot: stateRoot, installation: installation, executable: executable, read: validatedNodeHistoryRead, currentReadVersion: 2, identity: func(string) error { return nil }, probe: func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return 2, nil }}
}
func TestNodeWriteAdmissionChecksFutureRollbackReadCapability(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			a := nodeAdmissionFixture(t)
			data := []byte("trusted-old-controller")
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", data)
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.sha256", []byte(digestBytes(data)))
			calls := 0
			a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { calls++; return version, nil }
			err := a.CheckWrite(context.Background(), 2)
			if version == 2 && err != nil || version != 2 && err == nil || calls != 1 {
				t.Fatal("future rollback reader was not checked")
			}
		})
	}
}
func TestNodeAdmissionUnsealedChangedAndPendingControllersFence(t *testing.T) {
	for _, kind := range []string{"unsealed", "changed", "pending", "current-identity", "inventory-appeared", "current-mutated"} {
		t.Run(kind, func(t *testing.T) {
			a := nodeAdmissionFixture(t)
			data := []byte("trusted-old-controller")
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", data)
			if kind != "unsealed" {
				retainedFile(t, a.stateRoot, "update-backups/old/razvilka.sha256", []byte(digestBytes(data)))
			}
			switch kind {
			case "changed":
				retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", []byte("third-image"))
			case "pending":
				retainedFile(t, a.stateRoot, "self-update/current.json", []byte("{}"))
			case "current-identity":
				a.identity = func(string) error { return errors.New("kernel executable mismatch") }
			case "inventory-appeared":
				a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) {
					retainedFile(t, a.stateRoot, "update-backups/new/razvilka.bin", data)
					retainedFile(t, a.stateRoot, "update-backups/new/razvilka.sha256", []byte(digestBytes(data)))
					return 2, nil
				}
			case "current-mutated":
				a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) {
					if err := os.WriteFile(a.executable, []byte("different controller"), 0700); err != nil {
						t.Fatal(err)
					}
					return 2, nil
				}
			}
			if a.CheckWrite(context.Background(), 2) == nil {
				t.Fatal("untrusted/future controller admitted Xray history")
			}
		})
	}
}
func TestNodeReadableAndWriteAdmissionAreDifferent(t *testing.T) {
	a := nodeAdmissionFixture(t)
	ctx := context.Background()
	if err := a.CheckWrite(ctx, 2); err != nil {
		t.Fatal(err)
	}
	a.currentReadVersion = 1
	if err := a.CheckReadable(ctx); err != nil {
		t.Fatal("plain retained history cannot be read by reader1")
	}
	if a.CheckWrite(ctx, 2) == nil {
		t.Fatal("reader1 was allowed to create new history2")
	}
	retainedFile(t, a.configRoot, "nodes-private/nodes.private.json", retainedNodeFixture(t, true))
	if a.CheckReadable(ctx) == nil {
		t.Fatal("reader1 authorized a downgrade over Xray history")
	}
}
