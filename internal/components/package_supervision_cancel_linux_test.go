//go:build linux

package components

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestPackageSupervisorCancelledAfterSuccessfulParent(t *testing.T) {
	m, _, _ := prepareJournalFixture(t)
	tx, err := m.lockUpdateJournal()
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := lookup("nfqws2")
	images, err := m.snapshotConffiles(spec)
	if err != nil {
		t.Fatal(err)
	}
	m.Runner = execRunner{}
	if err := tx.prepare(spec, "1.3.1", m.rollbackPackage(spec, "1.3.1"), images); err != nil {
		t.Fatal(err)
	}
	if err := tx.phase(UpdateStarted); err != nil {
		t.Fatal(err)
	}
	id := tx.doc.TransactionID
	path := filepath.Join(m.updateJournalDir(), id)
	tx.close()
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	runner := fixtureSupervisedRunner(path)
	runner.supervisorEnv = append(runner.supervisorEnv, "RAZVILKA_DETACHED_STAGE=fork-hung", "RAZVILKA_DETACHED_ROOT="+path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runner.runSupervised(ctx, os.Args[0], []string{"-test.run=^TestPackageDetachedFixture$"}, packageSupervision{Schema: 1, TransactionID: id, Component: "nfqws2", Action: "upgrade", Containment: packageContainment, State: "intent"}, root, path)
		done <- err
	}()
	until := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(path, "ready")); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("fixture did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Give the zero-exit parent time to be reaped before signalling helper.
	time.Sleep(100 * time.Millisecond)
	journal, err := openUpdateRoot(m.updateJournalDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	r, err := readSupervision(journal, id, "nfqws2", "upgrade")
	if err != nil {
		t.Fatal(err)
	}
	start, _, err := processBirth(r.PID)
	if err != nil || start != r.Start {
		t.Fatal("fixture helper identity changed")
	}
	if err := syscall.Kill(r.PID, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("forced cleanup reported command success")
	}
	if ctx.Err() != nil {
		t.Fatal("test depended on cancelling parent context")
	}
	r, err = readSupervision(journal, id, "nfqws2", "upgrade")
	if err != nil || !r.Cancelled || r.ExitCode == 0 || !r.WaitECHILD {
		t.Fatalf("cleanup receipt %+v %v", r, err)
	}
	if err := m.Quiescence(context.Background(), id, "nfqws2"); err != nil {
		t.Fatal("reaped cleanup should prove inactivity", err)
	}
}
