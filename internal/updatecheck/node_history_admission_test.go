package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/ArtixSx/razvilka/internal/nodestore"
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

func TestNodeAdmissionRequiresMatchingTerminalHelperAndFileJournal(t *testing.T) {
	a := nodeAdmissionFixture(t)
	journal := filepath.Join(a.stateRoot, "self-update-files")
	for _, path := range []string{journal, filepath.Join(a.installation, "bin")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	data := []byte("trusted-current-controller")
	retainedFile(t, a.installation, "bin/razvilka", data)
	candidate := filepath.Join(a.stateRoot, "candidate-controller")
	if err := os.WriteFile(candidate, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := selfupdatejournal.Open(a.installation, journal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := "0123456789abcdef0123456789abcdef"
	check := func(context.Context) error { return nil }
	ctx := context.Background()
	if err := store.Prepare(ctx, id, []selfupdatejournal.File{{Target: "bin/razvilka", Candidate: candidate, SHA256: digestBytes(data)}}, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, id, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(ctx, id, false, check, check); err != nil {
		t.Fatal(err)
	}
	for _, matching := range []bool{true, false} {
		helperID := id
		if !matching {
			helperID = "1123456789abcdef0123456789abcdef"
		}
		raw, _ := json.Marshal(updateRecord{Owner: updaterOwner, Job: Job{ID: helperID, State: "completed"}})
		retainedFile(t, a.stateRoot, "self-update/current.json", raw)
		err := a.CheckWrite(ctx, 2)
		if matching && err != nil || !matching && err == nil {
			t.Fatal("helper/file terminal binding", matching, err)
		}
	}
}
func TestNodeWriteAdmissionChecksFutureRollbackReadCapability(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3, nodestore.ExactHistoryReadVersion + 1} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			a := nodeAdmissionFixture(t)
			data := []byte("trusted-old-controller")
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", data)
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.sha256", []byte(digestBytes(data)))
			calls := 0
			a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { calls++; return version, nil }
			err := a.CheckWrite(context.Background(), 2)
			allowed := version >= 2 && version <= nodestore.ExactHistoryReadVersion
			if allowed != (err == nil) || calls != 1 {
				t.Fatal("future rollback reader was not checked")
			}
		})
	}
}

func TestNodeReadableSeparatesLegacyRawAndUncheckedXHTTP(t *testing.T) {
	for _, test := range []struct {
		name     string
		material []byte
		required int
	}{
		{"legacy", retainedNodeFixture(t, false), 1}, {"raw", retainedNodeFixture(t, true), 2}, {"unchecked-xhttp", retainedXHTTPNodeFixture(t), 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := nodeAdmissionFixture(t)
			retainedFile(t, a.configRoot, "nodes-private/nodes.private.json", test.material)
			for version := 0; version <= nodestore.ExactHistoryReadVersion+1; version++ {
				a.currentReadVersion = version
				allowed := knownNodeHistoryReadVersion(version) && version >= test.required
				if allowed != (a.CheckReadable(context.Background()) == nil) {
					t.Fatal("wrong typed retained downgrade admission", version)
				}
			}
		})
	}
}

func TestNodeWriteAdmissionRequiresXHTTPBeforeFirstCheckAndRetainedAfterDeletion(t *testing.T) {
	for _, test := range []struct {
		name                           string
		current, wanted, old           int
		liveXHTTP, retainedXHTTP, pass bool
	}{
		{"raw-write2-old-reader2", 3, 2, 2, false, false, true},
		{"first-xhttp-write3-old-reader2", 3, 3, 2, false, false, false},
		{"live-xhttp-raw-write2-old-reader2", 3, 2, 2, true, false, false},
		{"deleted-xhttp-retained-backup-old-reader2", 3, 2, 2, false, true, false},
		{"xhttp-fleet3", 3, 3, 3, true, true, true},
		{"current-reader2-xhttp", 2, 3, 3, true, false, false},
		{"unknown-old-reader", 3, 2, 4, false, false, false},
		{"unknown-current-reader", 4, 2, 3, false, false, false},
		{"unknown-write-version", 3, 4, 3, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := nodeAdmissionFixture(t)
			a.currentReadVersion = test.current
			if test.liveXHTTP {
				retainedFile(t, a.configRoot, "nodes-private/nodes.private.json", retainedXHTTPNodeFixture(t))
			} else {
				retainedFile(t, a.configRoot, "nodes-private/nodes.private.json", retainedNodeFixture(t, true))
			}
			if test.retainedXHTTP {
				retainedFile(t, a.stateRoot, "backups/deleted-live/nodes.private.json", retainedXHTTPNodeFixture(t))
			}
			data := []byte("trusted-old-controller")
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", data)
			retainedFile(t, a.stateRoot, "update-backups/old/razvilka.sha256", []byte(digestBytes(data)))
			a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return test.old, nil }
			before, _ := readDirectoryImage(context.Background(), a.stateRoot)
			err := a.CheckWrite(context.Background(), test.wanted)
			if test.pass != (err == nil) {
				t.Fatal("wrong retained material/controller fleet admission", err)
			}
			after, readErr := readDirectoryImage(context.Background(), a.stateRoot)
			if readErr != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("write admission rewrote retained state", readErr)
			}
		})
	}
}

func TestNodeWriteAdmissionRefusesMaterialDriftDuringReaderObservations(t *testing.T) {
	a := nodeAdmissionFixture(t)
	a.currentReadVersion = 3
	data := []byte("trusted-old-controller")
	retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", data)
	retainedFile(t, a.stateRoot, "update-backups/old/razvilka.sha256", []byte(digestBytes(data)))
	xhttp := retainedXHTTPNodeFixture(t)
	a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) {
		retainedFile(t, a.stateRoot, "backups/appeared/nodes.private.json", xhttp)
		return 2, nil
	}
	if err := a.CheckWrite(context.Background(), 2); err == nil {
		t.Fatal("new XHTTP material borrowed prior RAW-only reader2 proof")
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
