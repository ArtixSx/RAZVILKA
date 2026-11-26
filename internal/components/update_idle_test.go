package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestInstalledIdleAcceptanceRequiresMatchingConfigurationAndTrustedInactivity(t *testing.T) {
	for _, fault := range []string{"none", "config", "version", "active", "second-active", "missing-quiescence", "historical"} {
		t.Run(fault, func(t *testing.T) {
			m, r, conf := prepareJournalFixture(t)
			result, err := m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "config" {
				if err := os.WriteFile(conf, []byte("foreign edit"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "version" {
				r.installed = "1.3.3"
			}
			if fault == "historical" {
				root, err := openUpdateRoot(m.updateJournalDir(), false)
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := readUpdateJournal(root)
				if err != nil {
					t.Fatal(err)
				}
				doc.SchemaVersion = 1
				doc.CandidateSnapshot = false
				doc.CandidateConfigs = nil
				tx := updateTransaction{manager: m, root: root, doc: doc}
				if err := tx.phase(UpdateAwaitingLive); err != nil {
					t.Fatal(err)
				}
				root.Close()
			}
			calls := 0
			request := ManagedRecoveryRequest{TransactionID: result.TransactionID, Component: "nfqws2", Action: "accept-installed-idle", QuiescenceCheck: allowRecovery, InactivityCheck: func(context.Context) error {
				calls++
				if fault == "active" || (fault == "second-active" && calls == 2) {
					return errors.New("runtime still active")
				}
				return nil
			}}
			if fault == "missing-quiescence" {
				request.QuiescenceCheck = nil
			}
			accepted, err := restartedManager(m).RecoverManagedUpdate(context.Background(), request, allowRecovery, nil)
			state, pending, readErr := m.PendingManagedUpdate()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if fault != "none" {
				if err == nil || !pending || accepted.InstalledIdleAccepted {
					t.Fatalf("unsafe idle accepted: %+v %+v %v", accepted, state, err)
				}
				return
			}
			if err != nil || pending || state.Phase != UpdateAcceptedIdle || !accepted.InstalledIdleAccepted || calls != 2 {
				t.Fatalf("idle acceptance: %+v %+v %v calls=%d", accepted, state, err, calls)
			}
			view := View{Spec: Spec{ID: "nfqws2"}, Installed: true, InstalledVersion: state.AfterVersion}
			m.attachLifecycleVerification(&view)
			if view.Verification != "installed-idle-accepted" {
				t.Fatalf("idle misreported as live: %+v", view)
			}
		})
	}
}

func TestHistoricalUnknownHasNoQuiescenceReceipt(t *testing.T) {
	m, _, _ := prepareJournalFixture(t)
	m.updateFault = func(point string) error {
		if point == "after:upgrade-command" {
			return errors.New("interrupted")
		}
		return nil
	}
	_, _ = m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
	state, _, err := m.PendingManagedUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedManager(m).Quiescence(context.Background(), state.TransactionID, "nfqws2"); !errors.Is(err, ErrUpdateUnknown) {
		t.Fatal("historical command accepted without trusted receipt", err)
	}
}

func TestSupervisionReceiptRequiresKernelProof(t *testing.T) {
	path := t.TempDir()
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	id := "0123456789abcdef0123456789abcdef"
	if err := root.MkdirAll(id, 0700); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ownedfs.Open(filepath.Join(path, id))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	r := packageSupervision{Schema: 1, TransactionID: id, Component: "nfqws2", Action: "upgrade", Containment: packageContainment, State: "reaped", BootID: "00000000-0000-0000-0000-000000000001", CommandSHA256: digest([]byte("command")), PID: 2, Start: "1", Group: 2, ChildPID: 3, Reaped: 2}
	if err := writeSupervision(snapshot, r); err != nil {
		t.Fatal(err)
	}
	if _, err := readSupervision(root, id, "nfqws2", "upgrade"); !errors.Is(err, ErrUpdateUnknown) {
		t.Fatal("missing ECHILD accepted", err)
	}
	r.WaitECHILD = true
	if err := writeSupervision(snapshot, r); err != nil {
		t.Fatal(err)
	}
	if _, err := readSupervision(root, id, "nfqws2", "upgrade"); err != nil {
		t.Fatal(err)
	}
}
