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
	// This is one multi-phase fixture envelope, not a production effect timeout.
	// The copied race test executable is probed/hashed repeatedly and real workers
	// must finish their own ECHILD joins before the stopped checks can begin.
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	phase := func(name string) {
		t.Helper()
		t.Logf("native stopped fixture phase=%s elapsed=%s remaining=%s", name, time.Since(started).Round(time.Millisecond), time.Until(deadline).Round(time.Millisecond))
		if err := ctx.Err(); err != nil {
			t.Fatalf("native stopped fixture context at %s: %v", name, err)
		}
	}
	phase("start")
	oldDirectory := u.Directory
	newDirectory := t.TempDir()
	if err := os.Rename(filepath.Join(oldDirectory, review.ID), filepath.Join(newDirectory, review.ID)); err != nil {
		t.Fatal(err)
	}
	u.Directory = newDirectory
	// Native callbacks capture their trusted startup roots. Rebuild the
	// fixture binding after relocation, exactly as the copied worker does;
	// assigning a.directory alone leaves runtime readback on the old root.
	a = nativeFileAdapter(newDirectory, profile)
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
	if err := os.WriteFile(filepath.Join(a.installation, "razvilka/run/razvilka.pid"), []byte(fmt.Sprintf("%d\n", oldPanel.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	init := []byte(fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = stop ]; then kill -TERM %d; rm -f '%s'; fi\nexit 0\n", oldPanel.Process.Pid, filepath.Join(a.installation, "razvilka/run/razvilka.pid")))
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
	phase("before-reader-fleet")
	proof, err := a.sealJournalReaders(ctx, review, readyAuthority)
	if err != nil {
		t.Fatal("actual admitted reader probes", err)
	}
	phase("after-reader-fleet")
	controller, err := os.Stat(filepath.Join(job, "control.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native stopped fixture controllers=%d reviewed-files=%d controller-bytes=%d supervised-commands=4", len(proof.Controllers), len(review.Files), controller.Size())
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
	phase("files-prepared")
	retainedFile(t, a.installation, "etc/razvilka/admin.token", []byte("original private token"))
	retainedFile(t, a.installation, "etc/razvilka/admin.credentials.json", []byte(`{"fixture":"original credentials"}`))
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		phase("before-command-" + command)
		if err := store.Execute(ctx, review.ID, command, func(ctx context.Context) error {
			return a.AuthorityAction(ctx, review.ID, review.Revision, fileCommandAuthority(command))
		}, func(ctx context.Context) error { return a.Run(ctx, review.ID, command) }); err != nil {
			t.Fatal(command, err)
		}
		if command == "stop-old-panel" {
			_ = oldPanel.Wait()
			joined = true
		}
		phase("after-command-" + command)
	}
	if err := a.runtimeInactive(ctx, review.ID); err != nil {
		t.Fatal("parent-runtime-readback-after-quiesce", err)
	}
	quiet := func(ctx context.Context) error {
		if err := a.Quiescence(ctx, review.ID); err != nil {
			return fmt.Errorf("native-file-quiescence: %w", err)
		}
		return nil
	}
	start := func(ctx context.Context) error {
		if err := a.AuthorityAction(ctx, review.ID, review.Revision, "start/live"); err != nil {
			return fmt.Errorf("native-file-install-authority: %w", err)
		}
		return nil
	}
	rollback := func(ctx context.Context) error {
		return a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback")
	}
	admit := func(action string) selfupdatejournal.Admission {
		return func(ctx context.Context, effect string, begin func() error) error {
			if err := a.EffectAdmission(ctx, review.ID, action, effect, begin); err != nil {
				return fmt.Errorf("native-file-admission-%s: %w", effect, err)
			}
			return nil
		}
	}
	phase("before-file-install")
	if err := store.InstallAdmitted(ctx, review.ID, start, quiet, admit("start/live")); err != nil {
		t.Fatal(err)
	}
	phase("after-file-install")
	if err := store.RestoreAdmitted(ctx, review.ID, rollback, quiet, admit("replace-to-rollback")); err != nil {
		t.Fatal(err)
	}
	phase("after-file-restore")
	if err := os.WriteFile(filepath.Join(a.installation, "etc/razvilka/admin.token"), []byte("candidate private token"), 0600); err != nil {
		t.Fatal(err)
	}
	phase("before-command-restore-private-state")
	if err := store.Execute(ctx, review.ID, "restore-private-state", rollback, func(ctx context.Context) error { return a.Run(ctx, review.ID, "restore-private-state") }); err != nil {
		t.Fatal(err)
	}
	phase("after-command-restore-private-state")
	if err := a.verifyPrivateRestore(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admin.token", "admin.credentials.json"} {
		path := filepath.Join(a.installation, "etc/razvilka", name)
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		phase("before-widened-mode-restore-refusal-" + name)
		restoreErr := a.restorePrivateSnapshot(ctx, review.ID)
		phase("after-widened-mode-restore-refusal-" + name)
		if restoreErr == nil {
			t.Fatal("equal bytes bypassed widened private mode before restore", name)
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0644 {
			t.Fatal("refusal silently repaired mode", name, err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		} // fixture cleanup only
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
	phase("actual-echild-verified")
	if _, err := operationgate.RequestSelfUpdateStop(ctx, profile.Control, review.ID, review.Revision); err != nil {
		t.Fatal(err)
	}
	// Use the public typed Stop read to preserve every binding. No reset API
	// is used by this path, and an attempted new probe is denied by the lock.
	stop, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control)
	if err != nil || !present || !stop.Stopped {
		t.Fatal(stop, err)
	}
	phase("durable-stop-recorded")
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
	phase("before-stopped-probe-refusal")
	_, probeErr := a.probeJournalReader(ctx, review, selfupdatejournal.BinaryImage{Path: filepath.Join(job, "control.bin"), SHA256: review.OldExecutableSHA256})
	phase("after-stopped-probe-refusal")
	if probeErr == nil {
		t.Fatal("Stop admitted a new probe")
	}
	for _, name := range []string{"admin.token", "admin.credentials.json"} {
		path := filepath.Join(a.installation, "etc/razvilka", name)
		before, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		phase("before-widened-mode-settlement-refusal-" + name)
		settlementErr := a.SettleStoppedRollback(ctx, review.ID, authority)
		phase("after-widened-mode-settlement-refusal-" + name)
		if settlementErr == nil {
			t.Fatal("terminal accepted unchanged private bytes with widened mode", name)
		}
		after, _ := os.ReadFile(filepath.Join(a.fileJournal, review.ID, "receipt.json"))
		if string(before) != string(after) {
			t.Fatal("metadata refusal published terminal", name)
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		} // fixture cleanup only
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
	phase("before-missing-echild-refusal")
	settlementErr := a.SettleStoppedRollback(ctx, review.ID, authority)
	phase("after-missing-echild-refusal")
	if !errors.Is(settlementErr, ErrFileCommandUnsettled) {
		t.Fatal("absence bypassed missing ECHILD", settlementErr)
	}
	if err := writeFileCommand(root, original); err != nil {
		t.Fatal(err)
	}
	phase("before-first-settlement")
	if err := a.SettleStoppedRollback(ctx, review.ID, authority); err != nil {
		t.Fatal(err)
	}
	phase("after-first-settlement")
	phase("before-idempotent-settlement")
	if err := a.SettleStoppedRollback(ctx, review.ID, authority); err != nil {
		t.Fatal("idempotent stopped retry", err)
	}
	phase("after-idempotent-settlement")
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
	phase("before-live-finish-refusal")
	finishErr := a.Finish(ctx, review.ID, true)
	phase("after-live-finish-refusal")
	if finishErr == nil {
		t.Fatal("stopped data borrowed live Finish")
	}
	if afterStopStarts != 0 {
		t.Fatal("actual Start after preserved Stop", afterStopStarts)
	}
	phase("complete")
}
