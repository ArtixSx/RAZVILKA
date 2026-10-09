package updatecheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestRuntimeQuiesceInactiveReasonVocabularyIsClosedAndBounded(t *testing.T) {
	seen := map[string]bool{}
	for reasons := RuntimeQuiesceInactiveReasons(1); reasons <= quiesceInactiveAll; reasons++ {
		stage := RuntimeQuiesceInactiveFailureStage(reasons)
		if seen[stage] || len(stage) > 128 || runtimeQuiesceDiagnosticStage([]byte(RuntimeQuiesceFailureOutput(stage)+"\n")) != stage {
			t.Fatal("invalid bounded causal vocabulary", reasons, stage)
		}
		seen[stage] = true
		cause := errors.New("private cause must remain in chain")
		failure := externalBootstrapFailure("quiesce-"+stage, cause)
		if !errors.Is(failure, cause) || ExternalBootstrapFailureCategory(failure) != "quiesce-"+stage {
			t.Fatal("actual cause or public fixed label was lost")
		}
	}
	for _, reasons := range []RuntimeQuiesceInactiveReasons{0, 64, 255} {
		if RuntimeQuiesceInactiveFailureStage(reasons) != "runtime-inactivity" {
			t.Fatal("unknown reasons entered the diagnostic")
		}
	}
	for _, stage := range []string{"runtime-inactivity-pid-42", "runtime-inactivity-private/path", "runtime-inactivity-scoped-dns-nfq-kernel\nsecret", "runtime-inactivity-nfq-kernel-scoped-dns"} {
		if knownRuntimeQuiesceFailure(stage) || strings.Contains(RuntimeQuiesceFailureOutput(stage), stage) {
			t.Fatal("unrecognized or reordered data entered a fixed diagnostic")
		}
	}
}

func TestRuntimeQuiesceInactiveDiagnosticChild(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_QUIESCE_DIAGNOSTIC") != "actual-inactivity-child" {
		return
	}
	stage := RuntimeQuiesceInactiveFailureStage(QuiesceInactiveScopedDNS | QuiesceInactiveNFQKernel)
	os.Stderr.WriteString(RuntimeQuiesceFailureOutput(stage) + "\n")
	os.Exit(3)
}

func TestRuntimeQuiesceInactiveDiagnosticJoinsActualChildAndCause(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(program, "-test.run=^TestRuntimeQuiesceInactiveDiagnosticChild$")
	command.Env = append(os.Environ(), "RAZVILKA_TEST_QUIESCE_DIAGNOSTIC=actual-inactivity-child")
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
		t.Fatal("actual child refusal was lost", cause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := pipe.finish(ctx)
	stage := "runtime-inactivity-scoped-dns-nfq-kernel"
	if err != nil || runtimeQuiesceDiagnosticStage(data) != stage {
		t.Fatal("actual joined child causes were lost", err)
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
	if !errors.Is(failure, cause) || ExternalBootstrapFailureCategory(failure) != "quiesce-"+stage {
		t.Fatal("supervisor retained a different causal result")
	}
}
