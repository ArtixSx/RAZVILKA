package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Original producer custody, never recovered from a PID/path/receipt. The same
// Cmd.Start records birth before its sole Wait starts. A timeout cannot discard
// the eventual Wait result or turn terminal disk bytes into a process owner.
type nfqwsProbeProcessWait struct {
	self         *nfqwsProbeProcessWait
	mu           sync.Mutex
	execution    *nfqwsProbeExecution
	command      *exec.Cmd
	process      *os.Process
	intent       nfqws2ManagedProcessLease
	root         *nfqwsProbeProcessRoot
	birth        components.NFQWSSupervisionIdentity
	birthKnown   bool
	done         chan struct{}
	waitErr      error
	completed    bool
	ackAttempted bool
	ackImage     restorejournal.Image
}

func (w *nfqwsProbeProcessWait) complete(err error) {
	w.mu.Lock()
	w.waitErr, w.completed = err, true
	w.mu.Unlock()
	close(w.done)
}

func (w *nfqwsProbeProcessWait) acknowledge(ctx context.Context) (result nfqws2ManagedProcessLease, resultErr error) {
	if w == nil || w.self != w || ctx == nil || ctx.Err() != nil || w.execution == nil || w.execution.self != w.execution || w.execution.processWait != w || w.command == nil {
		return result, ErrNFQWSManagedProcessUnknown
	}
	select {
	case <-w.done:
	case <-ctx.Done():
		return result, ctx.Err()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.execution
	if !w.completed || w.waitErr != nil || !w.birthKnown || w.process == nil || w.command.Process != w.process || w.process.Pid != w.birth.PID || w.birth.Group != w.birth.PID || !reflect.DeepEqual(w.intent.Command, e.command) || w.intent.LaunchBinding == nil || e.resource == nil || *w.intent.LaunchBinding != e.resource.binding || w.root == nil {
		return result, errors.Join(ErrNFQWSManagedProcessUnknown, w.waitErr)
	}
	path := filepath.Join(w.intent.StateRoot, nfqws2LeaseFile)
	if err := nfqws2ManagedObservationPath(path); err != nil {
		return result, err
	}
	if err := w.root.current(ctx); err != nil {
		return result, err
	}
	target, err := restorejournal.OpenExistingFileTarget(path)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, target.Close()) }()
	if err := w.root.matchesTarget(ctx, target); err != nil {
		return result, err
	}
	image, err := target.Read(ctx)
	if err != nil {
		return result, err
	}
	actual, err := nfqws2DecodeManagedLease(image, w.intent.StateRoot, w.intent.Owner)
	if err != nil {
		return result, err
	}
	allowed := actual
	allowed.Receipt, allowed.Child, allowed.Acknowledged = w.intent.Receipt, w.intent.Child, false
	if !reflect.DeepEqual(allowed, w.intent) || actual.Receipt.PID != w.birth.PID || actual.Receipt.Group != w.birth.Group || actual.Receipt.Start != w.birth.Start || actual.Receipt.BootID != w.birth.BootID || actual.Receipt.State != "reaped" && actual.Receipt.State != "not-started" || !actual.Receipt.WaitECHILD {
		return result, ErrNFQWSManagedProcessUnknown
	}
	if actual.Acknowledged {
		if !w.ackAttempted || !image.Exists || !bytes.Equal(image.Data, w.ackImage.Data) {
			return result, ErrNFQWSManagedProcessUnknown
		}
		return actual, w.root.matchesTarget(ctx, target) // Only THIS original producer's previous ACK attempt.
	}
	actual.Acknowledged = true
	after, err := nfqws2ManagedLeaseImage(actual)
	if err != nil {
		return result, err
	}
	w.ackAttempted, w.ackImage = true, after
	if err := w.root.matchesTarget(ctx, target); err != nil {
		return result, err
	}
	if err := target.CompareAndSwap(ctx, image, after); err != nil {
		return result, err
	}
	closing, err := target.Read(ctx)
	if err != nil || !closing.Exists || !bytes.Equal(closing.Data, after.Data) {
		return result, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	return actual, w.root.matchesTarget(ctx, target)
}
