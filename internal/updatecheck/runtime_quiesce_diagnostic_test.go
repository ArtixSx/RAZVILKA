package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestRuntimeQuiesceDiagnosticChild(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_QUIESCE_DIAGNOSTIC") != "actual-pipe-child" {
		return
	}
	os.Stderr.WriteString(RuntimeQuiesceFailureOutput("authority-closing") + "\n")
	os.Exit(3)
}

func TestRuntimeQuiesceDiagnosticJoinsActualChildAndPreservesCause(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(program, "-test.run=^TestRuntimeQuiesceDiagnosticChild$")
	command.Env = append(os.Environ(), "RAZVILKA_TEST_QUIESCE_DIAGNOSTIC=actual-pipe-child")
	pipe, err := newFileQuiesceDiagnosticPipe(command)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := pipe.started(); err != nil {
		t.Fatal(err)
	}
	cause := command.Wait()
	var exited *exec.ExitError
	if !errors.As(cause, &exited) || exited.ExitCode() != 3 {
		t.Fatal("actual child did not refuse", cause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := pipe.finish(ctx)
	if err != nil || runtimeQuiesceDiagnosticStage(data) != "authority-closing" {
		t.Fatal("actual child stderr was not joined/classified", err)
	}
	root, err := ownedfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := retainRuntimeQuiesceDiagnostic(root, data); err != nil {
		t.Fatal(err)
	}
	failure := runtimeQuiesceCommandFailure(root, cause)
	if !errors.Is(failure, cause) || ExternalBootstrapFailureCategory(failure) != "quiesce-authority-closing" {
		t.Fatal("causal command failure was lost")
	}
}

func TestRuntimeQuiesceDiagnosticRejectsUnknownOutputAndPreservesPriorEvidence(t *testing.T) {
	for _, stage := range runtimeQuiesceFailureStages {
		if runtimeQuiesceDiagnosticStage([]byte(RuntimeQuiesceFailureOutput(stage)+"\n")) != stage {
			t.Fatal("closed stage was lost")
		}
	}
	for _, data := range [][]byte{nil, []byte("private-token/path/body"), []byte(RuntimeQuiesceFailureOutput("deactivate") + "\nprivate"), []byte("prefix\n" + RuntimeQuiesceFailureOutput("deactivate") + "\n")} {
		root, err := ownedfs.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := retainRuntimeQuiesceDiagnostic(root, data); err != nil {
			t.Fatal(err)
		}
		if _, err := root.Stat(runtimeQuiesceDiagnosticFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unknown child output was persisted")
		}
		root.Close()
	}
	path := t.TempDir()
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	prior := []byte("preserve unknown prior evidence")
	if err := os.WriteFile(filepath.Join(path, runtimeQuiesceDiagnosticFile), prior, 0600); err != nil {
		t.Fatal(err)
	}
	if err := retainRuntimeQuiesceDiagnostic(root, []byte(RuntimeQuiesceFailureOutput("deactivate")+"\n")); !errors.Is(err, os.ErrExist) {
		t.Fatal("prior diagnostic was replaced", err)
	}
	after, err := os.ReadFile(filepath.Join(path, runtimeQuiesceDiagnosticFile))
	if err != nil || !bytes.Equal(prior, after) {
		t.Fatal("prior evidence changed")
	}
	if got := RuntimeQuiesceFailureOutput("private-data"); got != "runtime quiesce refused; category=unknown" {
		t.Fatal("unknown stage escaped")
	}
}

func TestRuntimeQuiesceDiagnosticPipeDrainsOverflowAndJoinsCancellation(t *testing.T) {
	command := exec.Command("not-executed")
	pipe, err := newFileQuiesceDiagnosticPipe(command)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	written := make(chan error, 1)
	go func() {
		_, err := pipe.writer.Write(bytes.Repeat([]byte("private-data"), 100000))
		written <- errors.Join(err, pipe.writer.Close())
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := pipe.finish(ctx)
	if err != nil || len(data) != 512 || runtimeQuiesceDiagnosticStage(data) != "" {
		t.Fatal("overflow was blocked or classified", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	blocked, err := newFileQuiesceDiagnosticPipe(exec.Command("not-executed"))
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	stopped, stop := context.WithCancel(context.Background())
	stop()
	if _, err := blocked.finish(stopped); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrFileCommandUnsettled) {
		t.Fatal("cancelled reader was not joined", err)
	}
}
