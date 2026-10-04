//go:build linux

package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Root runs this natively. The copied fixture controller and private layout
// own no network object/listener. All process receipts come from real workers,
// subreaper wait4/ECHILD and sole parent Wait, never synthetic completion JSON.
func TestNativeStoppedSettlementActualECHILDAndPreservedStop(t *testing.T) {
	a, u, review, profile := nativeFileFixture(t, "delayed")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	oldDirectory := u.Directory
	newDirectory := t.TempDir()
	if err := os.Rename(filepath.Join(oldDirectory, review.ID), filepath.Join(newDirectory, review.ID)); err != nil {
		t.Fatal(err)
	}
	u.Directory, a.directory = newDirectory, newDirectory
	job := filepath.Join(newDirectory, review.ID)
	review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	saveStoppedReview(t, a, u, review)
	oldPanel := exec.Command(filepath.Join(job, "control.bin"), "fixture-old-panel")
	stdin, err := oldPanel.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := oldPanel.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := oldPanel.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		_ = stdin.Close()
		if !joined {
			_ = oldPanel.Process.Kill()
			_ = oldPanel.Wait()
		}
	}()
	ready := make([]byte, 6)
	if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "ready\n" {
		t.Fatal("old panel fixture readiness", err)
	}
	panelIdentity, err := fileProcessAt(oldPanel.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "var/run/razvilka.pid"), []byte(fmt.Sprintf("%d\n", oldPanel.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	init := []byte(fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = stop ]; then kill -TERM %d; rm -f '%s'; fi\nexit 0\n", oldPanel.Process.Pid, filepath.Join(a.installation, "var/run/razvilka.pid")))
	for _, path := range []string{filepath.Join(a.installation, "etc/init.d/S99razvilka"), filepath.Join(job, "bundle/scripts/S99razvilka")} {
		if err := os.WriteFile(path, init, 0755); err != nil {
			t.Fatal(err)
		}
	}
	review.OldInitSHA256 = digestBytes(init)
	u.record.Files["scripts/S99razvilka"] = review.OldInitSHA256
	u.record.ParentPID = panelIdentity.PID
	review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	parent, err := fileHelperProcess()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, parent, panelIdentity})
	if err := os.WriteFile(filepath.Join(job, "helper.identity.json"), identity, 0600); err != nil {
		t.Fatal(err)
	}
	saveStoppedReview(t, a, u, review)
	readyAuthority := func(ctx context.Context, id string) (SelfUpdateAuthority, error) {
		r, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control)
		if err != nil || !present || r.Stopped {
			return SelfUpdateAuthority{}, errors.Join(ErrFileProtocol, err)
		}
		return SelfUpdateAuthority{r.InstallationID, r.Sequence}, nil
	}
	proof, err := a.sealJournalReaders(ctx, review, readyAuthority)
	if err != nil {
		t.Fatal("actual admitted reader probes", err)
	}
	review.JournalReaders = proof
	saveStoppedReview(t, a, u, review)
	store, err := selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	okay := func(context.Context) error { return nil }
	if err := store.Prepare(ctx, review.ID, review.Files, okay, okay); err != nil {
		t.Fatal(err)
	}
	retainedFile(t, a.installation, "etc/razvilka/admin.token", []byte("original private token"))
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := store.Execute(ctx, review.ID, command, func(ctx context.Context) error {
			return a.AuthorityAction(ctx, review.ID, review.Revision, fileCommandAuthority(command))
		}, func(ctx context.Context) error { return a.Run(ctx, review.ID, command) }); err != nil {
			t.Fatal(command, err)
		}
		if command == "stop-old-panel" {
			_ = oldPanel.Wait()
			joined = true
		}
	}
	quiet := func(ctx context.Context) error { return a.Quiescence(ctx, review.ID) }
	start := func(ctx context.Context) error {
		return a.AuthorityAction(ctx, review.ID, review.Revision, "start/live")
	}
	rollback := func(ctx context.Context) error {
		return a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback")
	}
	admit := func(action string) selfupdatejournal.Admission {
		return func(ctx context.Context, effect string, begin func() error) error {
			return a.EffectAdmission(ctx, review.ID, action, effect, begin)
		}
	}
	if err := store.InstallAdmitted(ctx, review.ID, start, quiet, admit("start/live")); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreAdmitted(ctx, review.ID, rollback, quiet, admit("replace-to-rollback")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "etc/razvilka/admin.token"), []byte("candidate private token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(ctx, review.ID, "restore-private-state", rollback, func(ctx context.Context) error { return a.Run(ctx, review.ID, "restore-private-state") }); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPrivateRestore(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "restore-private-state"} {
		r, err := readFileCommand(root, review.ID, command)
		if err != nil || r.State != "reaped" || !r.WaitECHILD || r.Cancelled || r.ExitCode != 0 {
			t.Fatal("missing actual ECHILD", command, r, err)
		}
		if command == "quiesce-old-runtime" && r.Reaped < 2 {
			t.Fatal("detached descendant was not joined", r)
		}
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, profile.Control, review.ID, review.Revision); err != nil {
		t.Fatal(err)
	}
	// Use the public typed Stop read to preserve every binding. No reset API
	// is used by this path, and an attempted new probe is denied by the lock.
	stop, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control)
	if err != nil || !present || !stop.Stopped {
		t.Fatal(stop, err)
	}
	admission := a.admission
	afterStopStarts := 0
	a.admission = func(ctx context.Context, id, installation string, sequence uint64, action, effect string, begin func() error) error {
		return admission(ctx, id, installation, sequence, action, effect, func() error { afterStopStarts++; return begin() })
	}
	controlBefore, err := os.ReadFile(filepath.Join(profile.Control, "current-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	requestBefore, err := os.ReadFile(filepath.Join(profile.Control, "stop-"+review.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	authority := SelfUpdateStoppedSettlementAuthority{
		Check: func(ctx context.Context, id, installation string, sequence, revision uint64) error {
			fresh, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control)
			if err != nil || !present || !fresh.Stopped || fresh.TransactionID != id || fresh.InstallationID != installation || fresh.Sequence != sequence+1 || fresh.ConfigRevision != revision {
				return errors.Join(ErrFileProtocol, err)
			}
			return nil
		},
		AdmitReaders: func(ctx context.Context, id string, wanted int) error {
			return a.CheckRetainedJournalReaders(ctx, id, wanted)
		},
	}
	if _, err := a.probeJournalReader(ctx, review, selfupdatejournal.BinaryImage{Path: filepath.Join(job, "control.bin"), SHA256: review.OldExecutableSHA256}); err == nil {
		t.Fatal("Stop admitted a new probe")
	}
	original, err := readFileCommand(root, review.ID, "quiesce-old-runtime")
	if err != nil {
		t.Fatal(err)
	}
	broken := original
	broken.State, broken.WaitECHILD, broken.Reaped = "running", false, 0
	if err := writeFileCommand(root, broken); err != nil {
		t.Fatal(err)
	}
	if err := a.SettleStoppedRollback(ctx, review.ID, authority); !errors.Is(err, ErrFileCommandUnsettled) {
		t.Fatal("absence bypassed missing ECHILD", err)
	}
	if err := writeFileCommand(root, original); err != nil {
		t.Fatal(err)
	}
	if err := a.SettleStoppedRollback(ctx, review.ID, authority); err != nil {
		t.Fatal(err)
	}
	if err := a.SettleStoppedRollback(ctx, review.ID, authority); err != nil {
		t.Fatal("idempotent stopped retry", err)
	}
	after, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control)
	if err != nil || !present || after != stop {
		t.Fatal("settlement changed preserved Stop", after, err)
	}
	controlAfter, err := os.ReadFile(filepath.Join(profile.Control, "current-v1.json"))
	if err != nil || string(controlBefore) != string(controlAfter) {
		t.Fatal("Stop current bytes changed", err)
	}
	requestAfter, err := os.ReadFile(filepath.Join(profile.Control, "stop-"+review.ID+".json"))
	if err != nil || string(requestBefore) != string(requestAfter) {
		t.Fatal("Stop request bytes changed", err)
	}
	if err := a.Inspect(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.Finish(ctx, review.ID, true); err == nil {
		t.Fatal("stopped data borrowed live Finish")
	}
	if afterStopStarts != 0 {
		t.Fatal("actual Start after preserved Stop", afterStopStarts)
	}
}
