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
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Only the copied test executable handles this fixture dispatch. Production
// has no fixture profile/argv/env override. Every artifact stays in TempDir;
// the synthetic quiescer owns no network object and opens no listener.
type nativeFileProfile struct {
	Installation string `json:"installation"`
	Control      string `json:"control"`
	Scenario     string `json:"scenario"`
}

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "-self-update-read-version" {
		fmt.Println(SelfUpdateReadVersion) // copied fixture binary's actual CLI observation
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "fixture-old-panel" {
		_, _ = os.Stdout.Write([]byte("ready\n"))
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	if len(os.Args) > 1 && (os.Args[1] == "self-update-command-helper" || os.Args[1] == "self-update-runtime-quiesce") {
		binary, err := os.Executable()
		if err != nil || filepath.Base(binary) != "control.bin" {
			os.Exit(91)
		}
		job := filepath.Dir(binary)
		data, err := os.ReadFile(filepath.Join(job, "native-fixture.json"))
		var p nativeFileProfile
		if err != nil || decodeFileProtocol(data, &p) != nil || !filepath.IsAbs(p.Installation) || !filepath.IsAbs(p.Control) {
			os.Exit(92)
		}
		if os.Args[1] == "self-update-command-helper" {
			if len(os.Args) != 4 || filepath.Base(job) != os.Args[2] {
				os.Exit(93)
			}
			if p.Scenario == "unsettled-worker" {
				signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
				if os.WriteFile(filepath.Join(job, "worker-ready"), []byte("ready\n"), 0600) != nil {
					os.Exit(97)
				}
				for {
					time.Sleep(time.Hour)
				}
			}
			a := nativeFileAdapter(filepath.Dir(job), p)
			if err := runFileCommandWorker(a, os.Args[2], os.Args[3]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
			os.Exit(0)
		}
		if len(os.Args) != 5 || filepath.Base(job) != os.Args[2] {
			os.Exit(94)
		}
		if p.Scenario == "hung" {
			// The direct child exits0, leaving a detached adopted child.
			cmd := exec.Command("/bin/sh", "-c", "printf '%s\\n' ready > \"$1\"; while :; do sleep 1; done", "fixture", filepath.Join(job, "child-ready"))
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if cmd.Start() != nil {
				os.Exit(95)
			}
			_ = cmd.Process.Release()
			os.Exit(0)
		}
		// This delayed write must finish before the worker may publish ECHILD.
		cmd := exec.Command("/bin/sh", "-c", "sleep 0.3; printf '%s\\n' owned > \"$1\"", "fixture", filepath.Join(job, "late-write"))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if cmd.Start() != nil {
			os.Exit(96)
		}
		_ = cmd.Process.Release()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func nativeFileAdapter(directory string, p nativeFileProfile) *SelfUpdateFileAdapter {
	a := &SelfUpdateFileAdapter{directory: directory, installation: p.Installation, fileJournal: filepath.Join(p.Installation, "var/lib/razvilka/self-update-files"), owned: func(string) error { return nil }, layout: func(Deployment) error { return nil }, capabilities: func(context.Context, string) error { return nil }}
	a.stopCheck = func(ctx context.Context, id string) (bool, error) {
		r, present, err := operationgate.ReadSelfUpdateStop(ctx, p.Control)
		if !present && err == nil {
			err = operationgate.ErrSelfUpdateStopJournal
		}
		return r.Stopped, err
	}
	a.admission = func(ctx context.Context, id, installationID string, sequence uint64, action, effect string, begin func() error) error {
		if p.Scenario == "stop-before-child" && effect == "command-child-quiesce-old-runtime" {
			if _, err := operationgate.RequestSelfUpdateStop(ctx, p.Control, id, 7); err != nil {
				return err
			}
		}
		return operationgate.WithSelfUpdateEffectAdmission(ctx, p.Control, id, installationID, sequence, effect, begin)
	}
	a.runtimeInactive = func(ctx context.Context, id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(directory, id, "late-write"))
		if err != nil || string(data) != "owned\n" {
			return ErrFileProtocol
		}
		return nil
	}
	a.filesystem = func(ctx context.Context) error { return probePrivateFilesystems(ctx, p.Installation) }
	return a
}

func nativeFileFixture(t *testing.T, scenario string) (*SelfUpdateFileAdapter, *Updater, fileReview, nativeFileProfile) {
	t.Helper()
	a, u, r := fileAdapterFixture(t)
	old, err := os.ReadFile(u.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	p := nativeFileProfile{Installation: filepath.Join(u.Directory, "installation"), Control: filepath.Join(u.Directory, "control"), Scenario: scenario}
	for _, path := range []string{"bin", "etc/init.d", "etc/razvilka", "var/run", "var/lib/razvilka/self-update-files"} {
		if err := os.MkdirAll(filepath.Join(p.Installation, filepath.FromSlash(path)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := operationgate.InitializeSelfUpdateControl(context.Background(), p.Control)
	if err != nil {
		t.Fatal(err)
	}
	r.AuthorityInstallationID, r.AuthoritySequence = ready.InstallationID, ready.Sequence
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	r.OldExecutableSHA256 = digestBytes(data)
	job := filepath.Join(u.Directory, r.ID)
	init := []byte("#!/bin/sh\nexit 0\n")
	r.OldInitSHA256 = digestBytes(init)
	u.mu.Lock()
	u.record.ExecutableHash = r.OldExecutableSHA256
	u.record.Deployment.Executable = filepath.Join(p.Installation, "bin/razvilka")
	u.record.Deployment.Paths["config"] = filepath.Join(p.Installation, "etc/razvilka/config.json")
	u.record.Job.State, u.record.Job.HelperPID = "restarting", os.Getpid()
	u.record.Job.CanApply, u.record.Job.ReviewToken = false, ""
	u.record.Job.Release.Binary.Digest, u.record.Job.Release.Binary.Size = "sha256:"+r.OldExecutableSHA256, int64(len(data))
	u.record.Files["dist/"+u.record.Job.Release.Binary.Name] = r.OldExecutableSHA256
	u.record.Files["scripts/S99razvilka"] = r.OldInitSHA256
	for _, path := range []string{u.record.Deployment.Executable, filepath.Join(job, "control.bin"), filepath.Join(job, "bundle/dist", u.record.Job.Release.Binary.Name)} {
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(p.Installation, "etc/init.d/S99razvilka"), filepath.Join(job, "bundle/scripts/S99razvilka")} {
		if err := os.WriteFile(path, init, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(u.record.Deployment.Paths["config"], old, 0600); err != nil {
		t.Fatal(err)
	}
	u.Deployment = u.record.Deployment
	r.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, r.MigratedConfigSHA256)
	sealed, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(job, "file-review.json"), sealed, 0600); err != nil {
		t.Fatal(err)
	}
	u.record.FileReviewSHA256 = digestBytes(sealed)
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	u.mu.Unlock()
	profile, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(job, "native-fixture.json"), profile, 0600); err != nil {
		t.Fatal(err)
	}
	a = nativeFileAdapter(u.Directory, p)
	if err := sealFileHelperIdentity(a, r.ID, r); err != nil {
		t.Fatal(err)
	}
	return a, u, r, p
}

func TestNativeSelfUpdateCommandReapsDetachedDelayedChild(t *testing.T) {
	a, u, r, _ := nativeFileFixture(t, "delayed")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Run(ctx, r.ID, "quiesce-old-runtime"); err != nil {
		t.Fatal(err)
	}
	root, err := a.commandRoot(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt, err := readFileCommand(root, r.ID, "quiesce-old-runtime")
	if err != nil || receipt.State != "reaped" || !receipt.WaitECHILD || receipt.Cancelled || receipt.ExitCode != 0 || receipt.Reaped < 2 {
		t.Fatal("no durable all-child completion", receipt, err)
	}
	if data, err := os.ReadFile(filepath.Join(u.Directory, r.ID, "late-write")); err != nil || string(data) != "owned\n" {
		t.Fatal("worker escaped before adopted child completion", err)
	}
	if err := a.Run(ctx, r.ID, "quiesce-old-runtime"); err == nil {
		t.Fatal("known command replayed")
	}
}

func TestNativeSelfUpdateCommandStopBeforeActualChild(t *testing.T) {
	a, _, r, p := nativeFileFixture(t, "stop-before-child")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Run(ctx, r.ID, "quiesce-old-runtime"); err == nil {
		t.Fatal("Stop barrier admitted child")
	}
	root, err := a.commandRoot(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt, err := readFileCommand(root, r.ID, "quiesce-old-runtime")
	if err != nil || receipt.State != "not-started" || !receipt.WaitECHILD || !receipt.Cancelled || receipt.DirectPID != 0 {
		t.Fatal("pre-spawn rejection lost durable inactivity", receipt, err)
	}
	if _, err := os.Stat(filepath.Join(a.directory, r.ID, "late-write")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("forbidden child ran", err)
	}
	stop, present, err := operationgate.ReadSelfUpdateStop(ctx, p.Control)
	if err != nil || !present || !stop.Stopped || stop.Sequence != r.AuthoritySequence+1 {
		t.Fatal("Stop was cleared", stop, err)
	}
}

func TestNativeSelfUpdateCommandCancelledDirectExitZeroIsRejected(t *testing.T) {
	a, _, r, _ := nativeFileFixture(t, "hung")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, r.ID, "quiesce-old-runtime") }()
	ready := filepath.Join(a.directory, r.ID, "child-ready")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || errors.Is(err, ErrFileCommandUnsettled) {
		t.Fatal("cancellation returned without confirmed settlement", err)
	}
	assertNativeFileCommandSettled(t, a, r.ID)
}

// No polling after Run returns: the API boundary must already have joined the
// worker and read its durable all-child completion, even on an error return.
func assertNativeFileCommandSettled(t *testing.T, a *SelfUpdateFileAdapter, id string) {
	t.Helper()
	root, err := a.commandRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt, err := readFileCommand(root, id, "quiesce-old-runtime")
	if err != nil || receipt.State != "reaped" || !receipt.WaitECHILD || !receipt.Cancelled || receipt.ExitCode != 125 || receipt.Reaped < 2 {
		t.Fatal("Run returned before durable canceled ECHILD", receipt, err)
	}
	if err := fileCommandInactive(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if birth, _, err := fileBirth(receipt.Supervisor.PID); err == nil && birth == receipt.Supervisor.Start {
		t.Fatal("Run returned before joining the exact worker", receipt.Supervisor)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func waitNativeFileMarker(ctx context.Context, path string) error {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func TestNativeSelfUpdateCommandAdmissionErrorAfterStartJoinsWorker(t *testing.T) {
	a, _, r, _ := nativeFileFixture(t, "hung")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admit := a.admission
	rejected := errors.New("admission failed after actual worker Start")
	a.admission = func(ctx context.Context, id, installationID string, sequence uint64, action, effect string, begin func() error) error {
		if err := admit(ctx, id, installationID, sequence, action, effect, begin); err != nil {
			return err
		}
		if effect == "command-worker-quiesce-old-runtime" {
			if err := waitNativeFileMarker(ctx, filepath.Join(a.directory, id, "child-ready")); err != nil {
				return err
			}
			return rejected
		}
		return nil
	}
	if err := a.Run(ctx, r.ID, "quiesce-old-runtime"); !errors.Is(err, rejected) || errors.Is(err, ErrFileCommandUnsettled) {
		t.Fatal("post-Start rejection returned unconfirmed cleanup", err)
	}
	assertNativeFileCommandSettled(t, a, r.ID)
}

func TestNativeSelfUpdateCommandReceiptFailureJoinsWorker(t *testing.T) {
	for _, failure := range []string{"unreadable", "identity"} {
		t.Run(failure, func(t *testing.T) {
			a, _, r, _ := nativeFileFixture(t, "hung")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- a.Run(ctx, r.ID, "quiesce-old-runtime") }()
			if err := waitNativeFileMarker(ctx, filepath.Join(a.directory, r.ID, "child-ready")); err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			root, err := a.commandRoot(r.ID)
			if err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			defer root.Close()
			var running fileCommandReceipt
			for {
				running, err = readFileCommand(root, r.ID, "quiesce-old-runtime")
				if err == nil && running.State == "running" {
					break
				}
				if ctx.Err() != nil {
					cancel()
					<-done
					t.Fatal("worker never published running", running, err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if failure == "unreadable" {
				err = root.WriteAtomic("quiesce-old-runtime.process.json", []byte("{broken"), 0600)
			} else {
				running.Supervisor.Start += "0"
				err = writeFileCommand(root, running)
			}
			if err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			if err := <-done; err == nil || errors.Is(err, ErrFileCommandUnsettled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatal("receipt failure returned unconfirmed cleanup", err)
			}
			assertNativeFileCommandSettled(t, a, r.ID)
		})
	}
}

func TestNativeSelfUpdateCommandCleanupTimeoutRemainsUnknown(t *testing.T) {
	a, _, r, _ := nativeFileFixture(t, "unsettled-worker")
	worker := exec.Command(filepath.Join(a.directory, r.ID, "control.bin"), "self-update-command-helper", r.ID, "quiesce-old-runtime")
	worker.Env = commandEnvironment()
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.Wait(); close(done) }()
	defer func() { _ = worker.Process.Kill(); <-done }()
	readyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitNativeFileMarker(readyCtx, filepath.Join(a.directory, r.ID, "worker-ready")); err != nil {
		t.Fatal(err)
	}
	supervisor, err := fileProcessOf(worker.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := fileProcessOf(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	root, err := a.commandRoot(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	intent := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: r.ID, Command: "quiesce-old-runtime", State: "intent", Parent: parent}
	if err := writeFileCommand(root, intent); err != nil {
		t.Fatal(err)
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cleanupCancel()
	if err := settleFileCommandWorker(cleanupCtx, root, r.ID, intent.Command, worker.Process, done, parent, supervisor, nil); !errors.Is(err, ErrFileCommandUnsettled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unjoined worker was settled", err)
	}
	after, err := readFileCommand(root, r.ID, intent.Command)
	if err != nil || after != intent || fileCommandInactive(context.Background(), after) == nil || fileProcessMatches(supervisor) != nil {
		t.Fatal("cleanup timeout changed unknown receipt or killed its wait owner", after, err)
	}
}

func TestNativeSelfUpdateCommandEpochInstallationBinding(t *testing.T) {
	a, _, r, p := nativeFileFixture(t, "delayed")
	wrong := "0123456789abcdef0123456789abcdef"
	if wrong == r.AuthorityInstallationID {
		t.Fatal("unexpected fixture identity")
	}
	called := false
	if err := a.admission(context.Background(), r.ID, wrong, r.AuthoritySequence, "stop-owned", "command-worker-quiesce-old-runtime", func() error { called = true; return nil }); !errors.Is(err, operationgate.ErrSelfUpdateStopChanged) || called {
		t.Fatal("different installation same epoch admitted", err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(context.Background(), p.Control, r.ID, 7); err != nil {
		t.Fatal(err)
	}
	if err := a.Run(context.Background(), r.ID, "quiesce-old-runtime"); err == nil {
		t.Fatal("revoked epoch launched worker")
	}
	root, err := a.commandRoot(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt, err := readFileCommand(root, r.ID, "quiesce-old-runtime")
	if err != nil || receipt.State != "intent" {
		t.Fatal("worker launched after Stop", receipt, err)
	}
	if fileCommandInactive(context.Background(), receipt) == nil {
		t.Fatal("intent falsely supplied quiescence")
	}
}
