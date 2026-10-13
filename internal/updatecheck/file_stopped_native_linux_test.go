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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"golang.org/x/sys/unix"
)

// Private copied-controller layout; all H/S/C/R identities, Waits, process
// receipts, Stop admission and file/private restore effects are real. Fixed
// production-root selection and the complete dataplane registry remain Root's
// genuine future Stop acceptance, never a fixture environment override.
func TestNativeCandidateStoppedCompletionTwoCuts(t *testing.T) {
	for _, cut := range []string{"before", "after"} {
		t.Run(cut, func(t *testing.T) {
			a, u, review, profile := nativeFileFixture(t, "candidate-stopped-"+cut)
			oldJob := filepath.Join(a.directory, review.ID)
			// Keep Installation/Control outside the helper inventory, exactly
			// like the established native stopped fixture below. Reader admission
			// must still reject every non-job directory in the helper root.
			helperDirectory := t.TempDir()
			id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // Existing actual S fixture's job.
			job := filepath.Join(helperDirectory, id)
			if err := os.Rename(oldJob, job); err != nil {
				t.Fatal(err)
			}
			// nativeFileFixture sealed its setup process and original job. The
			// copied H must publish its own actual identity after it starts.
			if err := os.Remove(filepath.Join(job, "helper.identity.json")); err != nil {
				t.Fatal("remove setup-only helper identity", err)
			}
			u.Directory = helperDirectory
			a = nativeFileAdapter(helperDirectory, profile)
			u.record.Job.ID, review.ID = id, id
			u.record.CurrentVersion, review.OldVersion = "0.20.0", "0.20.0"
			u.record.Job.Release.Version, review.NewVersion = "0.20.1", "0.20.1"
			review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
			saveStoppedReview(t, a, u, review)
			entries, err := os.ReadDir(a.directory)
			if err != nil || u.Directory != a.directory || len(entries) != 2 || entries[0].Name() != id || !entries[0].IsDir() || entries[0].Type()&os.ModeSymlink != 0 || entries[1].Name() != "current.json" || entries[1].Type() != 0 {
				t.Fatal("helper inventory must contain only its real job and current record", err)
			}
			for _, path := range []string{profile.Installation, profile.Control} {
				relative, err := filepath.Rel(a.directory, path)
				info, statErr := os.Lstat(path)
				if err != nil || statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					t.Fatal("actual Installation/Control must remain outside the helper inventory", err, statErr)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			helper := exec.CommandContext(ctx, filepath.Join(job, "control.bin"), "self-update-helper", id)
			output, err := helper.CombinedOutput() // Actual original H, sole outer Wait.
			if err != nil {
				t.Fatalf("original H fixture: %v\n%s", err, output)
			}
			if ctx.Err() != nil {
				t.Fatal("fixture backstop cannot be PASS", ctx.Err())
			}
			store, err := a.OpenFileJournal()
			if err != nil {
				t.Fatal(err)
			}
			r, present, err := store.Current()
			store.Close()
			if err != nil || !present || r.Schema != selfupdatejournal.StoppedSchema || r.Phase != stoppedRollbackState {
				t.Fatal("actual H did not publish stopped terminal", r.Phase, err)
			}
			stop, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control)
			if err != nil || !present || !stop.Stopped || stop.TransactionID != id {
				t.Fatal("exact Stop was not preserved", err)
			}
			if err := a.Inspect(ctx, id); err != nil {
				t.Fatal("cold terminal inspection", err)
			}
		})
	}
}

func TestNativeCandidateStoppedCompletionHelperFixture(t *testing.T) {
	if len(os.Args) != 3 || os.Args[1] != "self-update-helper" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	job, id := filepath.Dir(binary), os.Args[2]
	data, err := os.ReadFile(filepath.Join(job, "native-fixture.json"))
	var profile nativeFileProfile
	if err != nil || decodeFileProtocol(data, &profile) != nil {
		t.Fatal(err)
	}
	a := nativeFileAdapter(filepath.Dir(job), profile)
	record, err := readAdapterRecord(a.directory, id)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(job, "file-review.json"))
	var review fileReview
	if err != nil || decodeFileProtocol(data, &review) != nil {
		t.Fatal(err)
	}
	u := &Updater{Directory: a.directory, Deployment: record.Deployment, record: record}
	oldPanel := exec.Command(binary, "fixture-old-panel")
	input, err := oldPanel.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := oldPanel.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := oldPanel.Start(); err != nil {
		t.Fatal(err)
	}
	oldWaited := false
	t.Cleanup(func() {
		input.Close()
		if !oldWaited {
			_ = oldPanel.Process.Kill()
			_ = oldPanel.Wait()
		}
	})
	readyBytes := make([]byte, 6)
	if _, err := io.ReadFull(output, readyBytes); err != nil || string(readyBytes) != "ready\n" {
		t.Fatal("old panel readiness", err)
	}
	old, err := fileProcessOf(oldPanel.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	u.record.ParentPID, u.record.Job.HelperPID = old.PID, os.Getpid()
	u.record.Job.State, u.record.Job.Stage, u.record.Job.CanCancel = "restarting", "file-protocol", false
	pidPath := filepath.Join(a.installation, "razvilka/run/razvilka.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(old.PID)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	init := []byte(fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = stop ]; then kill -TERM %d; rm -f '%s'; fi\nexit 0\n", old.PID, pidPath))
	for _, path := range []string{filepath.Join(a.installation, "etc/init.d/S99razvilka"), filepath.Join(job, "bundle/scripts/S99razvilka")} {
		if err := os.WriteFile(path, init, 0755); err != nil {
			t.Fatal(err)
		}
	}
	review.OldInitSHA256, u.record.Files["scripts/S99razvilka"] = digestBytes(init), digestBytes(init)
	review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	saveStoppedReview(t, a, u, review)
	// This API observes the current H and the actual live old-panel process;
	// its exclusive create must precede required reader/identity validation.
	if err := sealFileHelperIdentity(a, id, review); err != nil {
		t.Fatal("seal actual H and old-panel identity", err)
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil || identity.Process.PID != os.Getpid() || identity.OldPanel != old {
		t.Fatal("sealed helper must bind actual H and observed old panel")
	}
	// Private diagnosis only: the actual production seal/probe predicates and
	// original refusal stay intact. Never print paths, PIDs, argv, hashes, raw
	// child output or raw errors. Failure diagnostics only read existing facts.
	errorClass := func(err error) string {
		var exited *exec.ExitError
		switch {
		case err == nil:
			return "none"
		case errors.Is(err, context.DeadlineExceeded):
			return "deadline"
		case errors.Is(err, context.Canceled):
			return "cancelled"
		case errors.Is(err, operationgate.ErrSelfUpdateStopped):
			return "stopped"
		case errors.Is(err, os.ErrNotExist):
			return "missing"
		case errors.As(err, &exited):
			return "child-exit"
		case errors.Is(err, ErrFileProtocol):
			return "protocol"
		default:
			return "other"
		}
	}
	imageRole := func(image selfupdatejournal.BinaryImage) string {
		switch image.Path {
		case filepath.Join(a.installation, "bin/razvilka"):
			return "installed"
		case filepath.Join(a.directory, review.ID, "control.bin"):
			return "helper"
		}
		for _, file := range review.Files {
			if file.Target == "bin/razvilka" && file.Candidate == image.Path {
				return "candidate"
			}
		}
		return "retained"
	}
	admission := a.admission
	admissionCalls, authorityCalls, probeCalls := 0, 0, 0
	a.admission = func(c context.Context, jobID, installationID string, sequence uint64, action, effect string, begin func() error) error {
		admissionCalls++
		began := false
		var beginErr error
		admitErr := admission(c, jobID, installationID, sequence, action, effect, func() error {
			began = true
			beginErr = begin()
			return beginErr
		})
		t.Logf("reader-seal admission call=%d job_match=%t installation_match=%t epoch_match=%t action_match=%t effect_match=%t began=%t begin=%s result=%s context=%s", admissionCalls, jobID == review.ID, installationID == review.AuthorityInstallationID, sequence == review.AuthoritySequence, action == "start/live", effect == journalReaderProbeEffect, began, errorClass(beginErr), errorClass(admitErr), errorClass(c.Err()))
		return admitErr
	}
	sealStarted := time.Now()
	proof, err := a.sealJournalReadersWithProbe(ctx, review, func(c context.Context, _ string) (SelfUpdateAuthority, error) {
		stop, present, err := operationgate.ReadSelfUpdateStop(c, profile.Control)
		authorityCalls++
		t.Logf("reader-seal authority call=%d present=%t stopped=%t installation_match=%t epoch_match=%t result=%s", authorityCalls, present, stop.Stopped, stop.InstallationID == review.AuthorityInstallationID, stop.Sequence == review.AuthoritySequence, errorClass(err))
		if err != nil || !present || stop.Stopped {
			return SelfUpdateAuthority{}, errors.Join(ErrFileProtocol, err)
		}
		return SelfUpdateAuthority{stop.InstallationID, stop.Sequence}, nil
	}, func(c context.Context, r fileReview, image selfupdatejournal.BinaryImage) (int, error) {
		probeCalls++
		started := time.Now()
		t.Logf("reader-seal probe call=%d role=%s started=true", probeCalls, imageRole(image))
		version, probeErr := a.probeJournalReader(c, r, image)
		t.Logf("reader-seal probe call=%d role=%s reader=%d elapsed_ms=%d result=%s context=%s", probeCalls, imageRole(image), version, time.Since(started).Milliseconds(), errorClass(probeErr), errorClass(c.Err()))
		return version, probeErr
	})
	a.admission = admission
	t.Logf("reader-seal boundary proof_present=%t proof_valid=%t authority_calls=%d probe_calls=%d admission_calls=%d elapsed_ms=%d result=%s", proof != nil, validJournalReaderProof(proof), authorityCalls, probeCalls, admissionCalls, time.Since(sealStarted).Milliseconds(), errorClass(err))
	if err != nil {
		sealErr := err // Diagnostics cannot replace or satisfy this refusal.
		current, currentErr := readAdapterRecord(a.directory, id)
		t.Logf("reader-seal record result=%s owner_match=%t job_match=%t old_version_match=%t new_version_match=%t expected_old_version=%t expected_new_version=%t installation_match=%t executable_match=%t review_owner_valid=%t", errorClass(currentErr), current.Owner == updaterOwner, current.Job.ID == review.ID, current.CurrentVersion == review.OldVersion, current.Job.Release != nil && current.Job.Release.Version == review.NewVersion, review.OldVersion == "0.20.0", review.NewVersion == "0.20.1", profile.Installation == a.installation, current.ExecutableHash == review.OldExecutableSHA256, validFileReviewOwner(review, current))
		boundRecord, boundReview, boundErr := a.loadBoundReview(ctx, id, true, false)
		t.Logf("reader-seal bound-review result=%s record_match=%t review_match=%t", errorClass(boundErr), reflect.DeepEqual(boundRecord, current), reflect.DeepEqual(boundReview, review))
		formatsErr := a.checkHelperProcessFormats(ctx, current, review)
		t.Logf("reader-seal helper-formats result=%s", errorClass(formatsErr))
		if root, rootErr := a.commandRoot(id); rootErr == nil {
			identityData, identityErr := root.ReadLimited("helper.identity.json", 4096)
			root.Close()
			var identity fileHelperIdentity
			decoded := identityErr == nil && decodeFileProtocol(identityData, &identity) == nil
			t.Logf("reader-seal helper-identity result=%s decoded=%t schema_match=%t job_match=%t helper_valid=%t old_panel_valid=%t helper_image_match=%t old_image_match=%t boot_match=%t helper_record_match=%t old_panel_record_match=%t helper_is_actual_h=%t preparation_parent_match=%t", errorClass(identityErr), decoded, identity.Schema == selfUpdateProtocolSchema, identity.ID == review.ID, validFileProcess(identity.Process), validFileProcess(identity.OldPanel), identity.Process.ExecutableSHA256 == reviewedHelperSHA(review), identity.OldPanel.ExecutableSHA256 == review.OldExecutableSHA256, identity.Process.Boot == identity.OldPanel.Boot, identity.Process.PID == current.Job.HelperPID, identity.OldPanel.PID == current.ParentPID, identity.Process.PID == os.Getpid(), review.PreparationParent == nil || *review.PreparationParent == identity.OldPanel)
		} else {
			t.Logf("reader-seal helper-identity root=%s", errorClass(rootErr))
		}
		required, requiredErr := a.requiredJournalReadVersion(ctx)
		t.Logf("reader-seal required reader=%d result=%s", required, errorClass(requiredErr))
		images, inventoryErr := a.journalReaderImages(ctx, review)
		t.Logf("reader-seal diagnostic-inventory images=%d result=%s", len(images), errorClass(inventoryErr))
		t.Fatalf("reader-seal original refusal: %s", errorClass(sealErr))
	}
	review.JournalReaders = proof
	saveStoppedReview(t, a, u, review)
	store, err := a.OpenFileJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	okay := func(context.Context) error { return nil }
	if err := store.Prepare(ctx, id, review.Files, okay, okay); err != nil {
		t.Fatal(err)
	}
	retainedFile(t, a.installation, "etc/razvilka/admin.token", []byte("original private token"))
	retainedFile(t, a.installation, "etc/razvilka/admin.credentials.json", []byte(`{"fixture":"original credentials"}`))
	for _, command := range []string{"stop-old-panel", "prepare-private-state"} {
		if err := store.Execute(ctx, id, command, okay, func(c context.Context) error { return a.Run(c, id, command) }); err != nil {
			t.Fatal(err)
		}
		if command == "stop-old-panel" {
			_ = oldPanel.Wait()
			oldWaited = true
		}
	}
	if err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
		if err := store.Execute(held, id, "quiesce-old-runtime", okay, func(c context.Context) error { return nativeStoppedQuiesceJoin(c, a, binary, id) }); err != nil {
			return err
		}
		quiet := func(c context.Context) error { return a.Quiescence(c, id) }
		if err := store.Install(held, id, okay, quiet); err != nil {
			return err
		}
		w, final := nativeStoppedCandidateDeath(t, held, a, store, binary, job, id)
		request := func() {
			if _, err := operationgate.RequestSelfUpdateStop(held, profile.Control, id, review.Revision); err != nil {
				t.Fatal(err)
			}
		}
		if profile.Scenario == "candidate-stopped-before" {
			request()
		}
		if err := store.Execute(held, id, "stop-candidate-panel", okay, func(cctx context.Context) error {
			intent, _, err := store.Current()
			if err != nil {
				return err
			}
			if err := executeCandidateCleanup(cctx, w, final, func() error { return candidateProcessesAbsent(cctx, w.ready) }, func(begin func() error) error {
				return a.EffectAdmission(cctx, id, "stop-owned", candidateKnownAbsentPIDEffect, begin)
			}, removeCandidatePID); err != nil {
				return err
			}
			if err := a.filePanelAbsent(cctx); err != nil {
				return err
			}
			return sealCandidateAbsenceCompletion(cctx, w, final, intent, a.candidateStoppedCompletionFacts, a.candidateStoppedCompletionObservation)
		}); err != nil {
			return err
		}
		if profile.Scenario == "candidate-stopped-after" {
			request()
		}
		controlBefore, err := os.ReadFile(filepath.Join(profile.Control, "current-v1.json"))
		if err != nil {
			return err
		}
		requestBefore, err := os.ReadFile(filepath.Join(profile.Control, "stop-"+id+".json"))
		if err != nil {
			return err
		}
		admit := func(c context.Context, effect string, begin func() error) error {
			return a.EffectAdmission(c, id, "replace-to-rollback", effect, begin)
		}
		if err := store.RestoreAdmitted(held, id, okay, quiet, admit); err != nil {
			return err
		}
		if err := store.Execute(held, id, "restore-private-state", okay, func(c context.Context) error { return a.Run(c, id, "restore-private-state") }); err != nil {
			return err
		}
		r, present, err := store.Current()
		if err != nil || !present || r.Command != "restore-private-state" || r.Phase != "command-finished" {
			return errors.Join(ErrFileProtocol, err)
		}
		if err := a.AuthorityAction(held, id, review.Revision, "start/live"); !errors.Is(err, ErrFileAuthorityStopped) {
			return errors.Join(ErrFileProtocol, err)
		}
		if _, err := os.Stat(filepath.Join(job, "stop-candidate-panel.process.json")); !errors.Is(err, os.ErrNotExist) {
			return ErrFileProtocol
		}
		authority := nativeStoppedCandidateAuthority(a, profile.Control)
		if err := a.SettleStoppedRollback(ctx, id, authority); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cold first settlement did not refuse missing ledger", err)
		}
		legacyRuntime := a.runtimeInactive
		a.runtimeInactive = func(c context.Context, job string) error {
			if c.Value(candidateStoppedReadKey{}) == nil {
				return legacyRuntime(c, job)
			}
			return a.VerifyCurrentOrdinaryInstallerControllerRole(c, job)
		}
		if err := a.SettleStoppedRollback(held, id, authority); err != nil {
			return err
		}
		controlAfter, err := os.ReadFile(filepath.Join(profile.Control, "current-v1.json"))
		if err != nil {
			return err
		}
		requestAfter, err := os.ReadFile(filepath.Join(profile.Control, "stop-"+id+".json"))
		if err != nil {
			return err
		}
		if string(controlBefore) != string(controlAfter) || string(requestBefore) != string(requestAfter) {
			return ErrFileProtocol
		}
		return a.Inspect(held, id)
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.SettleStoppedRollback(ctx, id, nativeStoppedCandidateAuthority(a, profile.Control)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("exited H was reconstructed for cold retry", err)
	}
}

func nativeStoppedCandidateAuthority(a *SelfUpdateFileAdapter, control string) SelfUpdateStoppedSettlementAuthority {
	return SelfUpdateStoppedSettlementAuthority{
		Check: func(ctx context.Context, id, installation string, sequence, revision uint64) error {
			stop, present, err := operationgate.ReadSelfUpdateStop(ctx, control)
			if err != nil || !present || !stop.Stopped || stop.TransactionID != id || stop.InstallationID != installation || stop.Sequence != sequence+1 || stop.ConfigRevision != revision {
				return errors.Join(ErrFileProtocol, err)
			}
			return nil
		}, AdmitReaders: func(ctx context.Context, id string, reader int) error {
			return a.CheckRetainedJournalReaders(ctx, id, reader)
		},
	}
}

func nativeStoppedQuiesceJoin(ctx context.Context, a *SelfUpdateFileAdapter, binary, id string) error {
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, err := fileProcessOf(os.Getpid())
	if err != nil {
		return err
	}
	r := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: id, Command: "quiesce-old-runtime", State: "intent", Parent: parent}
	if err := writeFileCommand(root, r); err != nil {
		return err
	}
	worker := exec.CommandContext(ctx, binary, "self-update-command-helper", id, r.Command)
	worker.Stderr = os.Stderr
	if err := a.EffectAdmission(ctx, id, "stop-owned", "command-worker-"+r.Command, worker.Start); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited {
			_ = worker.Process.Kill()
			_ = worker.Wait()
		}
	}()
	r.Supervisor, err = fileProcessOf(worker.Process.Pid)
	if err != nil {
		return err
	}
	w, err := beginOrdinaryInstallerWait(ctx, a, id, worker, parent, r.Supervisor)
	if err != nil {
		return err
	}
	r.State = "armed"
	if err := writeFileCommand(root, r); err != nil {
		return err
	}
	err = worker.Wait()
	waited = true
	w.observeWait(err)
	if err != nil {
		return err
	}
	final, err := readFileCommand(root, id, r.Command)
	if err != nil {
		return err
	}
	return w.complete(ctx, final)
}

func nativeStoppedCandidateDeath(t *testing.T, ctx context.Context, a *SelfUpdateFileAdapter, store *selfupdatejournal.Store, binary, job, id string) (*candidateStartWait, fileCommandReceipt) {
	t.Helper()
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(binary, "-test.run=^TestCandidateCleanupNativeSupervisorFixture$")
	worker.Env = append(os.Environ(), "RAZVILKA_TEST_CANDIDATE_ROLE=supervisor", "RAZVILKA_TEST_CANDIDATE_DIRECTORY="+job)
	worker.Stdin, worker.Stderr = input, os.Stderr
	var once sync.Once
	done := make(chan struct{})
	var waitErr error
	startWait := func() { once.Do(func() { go func() { waitErr = worker.Wait(); close(done) }() }) }
	t.Cleanup(func() {
		input.Close()
		release.Close()
		if worker.Process != nil {
			startWait()
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				_ = worker.Process.Kill()
				<-done
			}
		}
	})
	root, err := a.commandRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var w *candidateStartWait
	var ready fileCommandReceipt
	if err := store.Execute(ctx, id, "start-candidate-panel", func(c context.Context) error { return a.AuthorityAction(c, id, 7, "start/live") }, func(c context.Context) error {
		if err := worker.Start(); err != nil {
			return err
		}
		input.Close()
		parent, err := fileProcessOf(os.Getpid())
		if err != nil {
			return err
		}
		supervisor, err := fileProcessOf(worker.Process.Pid)
		if err != nil {
			return err
		}
		w, err = beginCandidateStartWait(c, a, id, worker, parent, supervisor)
		if err != nil {
			return err
		}
		w.record, w.review, err = a.load(c, id)
		if err != nil {
			return err
		}
		w.identity, err = a.helperIdentity(id, w.review)
		if err != nil {
			return err
		}
		for {
			ready, err = readFileCommand(root, id, "start-candidate-panel")
			if err == nil && ready.State == "runtime-ready" {
				break
			}
			if c.Err() != nil {
				return c.Err()
			}
			time.Sleep(10 * time.Millisecond)
		}
		pid, err := captureCandidatePID(job, ready.Runtime.PID, syscall.O_NOFOLLOW)
		if err != nil {
			return err
		}
		if err := w.rememberReady(c, ready, pid); err != nil {
			pid.close()
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(ready.Runtime.PID, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	actual, err := fileProcessOf(ready.Runtime.PID)
	if err != nil || actual != ready.Runtime {
		t.Fatal("runtime kernel handle identity", err)
	}
	if err := unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	release.Close()
	startWait()
	<-done
	w.observeWait(waitErr)
	final, err := readFileCommand(root, id, "start-candidate-panel")
	if err != nil || final.State != "reaped" || final.Reaped != 2 || !final.WaitECHILD || waitErr != nil {
		t.Fatal("actual sole candidate Wait/ECHILD", err, waitErr)
	}
	return w, final
}

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
