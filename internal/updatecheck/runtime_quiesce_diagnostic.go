package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const runtimeQuiesceDiagnosticFile = "quiesce-old-runtime.diagnostic"

var runtimeQuiesceFailureStages = append([]string{"entry", "provider", "authority-opening", "independent-opening", "manager-construction", "installer-role-binding", "deactivate", "runtime-inactivity", "authority-closing", "independent-closing"}, runtimeQuiesceInactiveFailureStages()...)

func knownRuntimeQuiesceFailure(stage string) bool {
	for _, known := range runtimeQuiesceFailureStages {
		if stage == known {
			return true
		}
	}
	return false
}

func RuntimeQuiesceFailureOutput(stage string) string {
	if !knownRuntimeQuiesceFailure(stage) {
		stage = "unknown"
	}
	return "runtime quiesce refused; category=" + stage
}

func runtimeQuiesceDiagnosticStage(data []byte) string {
	for _, stage := range runtimeQuiesceFailureStages {
		if bytes.Equal(data, []byte(RuntimeQuiesceFailureOutput(stage)+"\n")) {
			return stage
		}
	}
	return ""
}

// Only an exact closed child diagnostic is retained. Arbitrary child output is
// drained into a bounded buffer and discarded; a prior file is never replaced.
func retainRuntimeQuiesceDiagnostic(root *ownedfs.Root, data []byte) error {
	if runtimeQuiesceDiagnosticStage(data) == "" {
		return nil
	}
	f, err := root.OpenFile(runtimeQuiesceDiagnosticFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	return syncSelfUpdateDirectory(root)
}

func runtimeQuiesceCommandFailure(root *ownedfs.Root, cause error) error {
	data, err := root.ReadLimited(runtimeQuiesceDiagnosticFile, 512)
	if err != nil {
		return errors.Join(ErrFileProtocol, cause)
	}
	stage := runtimeQuiesceDiagnosticStage(data)
	if stage == "" {
		return errors.Join(ErrFileProtocol, cause)
	}
	return externalBootstrapFailure("quiesce-"+stage, cause)
}

// The worker uses wait4 itself, so exec.Cmd.Wait cannot join stderr copying.
// Own this pipe explicitly and join its reader before inspecting output or
// relinquishing the actual supervisor. No command receipt substitutes for it.
type fileQuiesceDiagnosticPipe struct {
	reader *os.File
	writer *os.File
	done   chan struct{}
	output cappedOutput
	err    error
}

func newFileQuiesceDiagnosticPipe(command *exec.Cmd) (*fileQuiesceDiagnosticPipe, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	p := &fileQuiesceDiagnosticPipe{reader: r, writer: w, done: make(chan struct{}), output: cappedOutput{maximum: 512}}
	command.Stderr = w
	go func() {
		// Hide bytes.Buffer's promoted ReadFrom, which would bypass the cap.
		_, p.err = io.Copy(struct{ io.Writer }{&p.output}, r)
		close(p.done)
	}()
	return p, nil
}

func (p *fileQuiesceDiagnosticPipe) started() error { return p.writer.Close() }

func (p *fileQuiesceDiagnosticPipe) finish(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		p.Close()
		return nil, ErrFileCommandUnsettled
	}
	if err := ctx.Err(); err != nil {
		p.Close()
		return nil, errors.Join(ErrFileCommandUnsettled, err)
	}
	select {
	case <-p.done:
		return append([]byte(nil), p.output.Bytes()...), errors.Join(p.err, ctx.Err())
	case <-ctx.Done():
		p.Close()
		return nil, errors.Join(ErrFileCommandUnsettled, ctx.Err())
	}
}

func (p *fileQuiesceDiagnosticPipe) Close() {
	p.writer.Close()
	p.reader.Close()
	<-p.done
}
