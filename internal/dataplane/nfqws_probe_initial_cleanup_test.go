package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Local association model only; it cannot issue cleanupCurrent or a process
// grant. The actual original producer/queue/COMMON path is a native gate.
func initialProbeCleanupFixture(t *testing.T) (*nfqwsExecutionAssembly, *nfqwsProbeExecution, context.Context) {
	t.Helper()
	command, binding, _, _ := nfqws2ManagedStartFixture(t)
	consumer := &ManagedNFQWSProbeConsumer{adapter: &NFQWS2Adapter{}}
	consumer.self = consumer
	e := &nfqwsProbeExecution{consumer: consumer, command: command, resource: &NFQWSExecutionResource{binding: binding}, binding: &NFQWSScopedBinding{}}
	e.self = e
	e.open.Store(true)
	e.executing.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, nfqwsProbeExecutionKey{}, e)
	a := &nfqwsExecutionAssembly{ctx: ctx, adapter: consumer.adapter, command: command, resource: e.resource, binding: e.binding}
	ctx = context.WithValue(ctx, nfqwsProbeCleanupKey{}, e)
	w := &nfqwsProbeProcessWait{execution: e, root: &nfqwsProbeProcessRoot{}, command: exec.Command("never-started-association-model"), done: make(chan struct{}), intent: nfqws2ManagedProcessLease{Command: command, LaunchBinding: &binding}}
	w.self = w
	e.processWait = w
	return a, e, ctx
}

func TestNFQWSProbeInitialCleanupOriginalAssociations(t *testing.T) {
	for _, mode := range []string{"same", "nil", "unbounded", "canceled", "closed", "not-executing", "foreign-context", "foreign-cleanup", "consumer", "resource", "binding", "command", "result", "wait-copy", "wait-execution", "wait-command", "wait-root", "wait-channel", "wait-binding"} {
		t.Run(mode, func(t *testing.T) {
			a, e, ctx := initialProbeCleanupFixture(t)
			w := e.processWait
			switch mode {
			case "nil":
				ctx = nil
			case "unbounded":
				ctx = context.WithValue(context.WithValue(context.Background(), nfqwsProbeExecutionKey{}, e), nfqwsProbeCleanupKey{}, e)
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "closed":
				e.open.Store(false)
			case "not-executing":
				e.executing.Store(false)
			case "foreign-context":
				ctx = context.WithValue(ctx, nfqwsProbeExecutionKey{}, &nfqwsProbeExecution{})
			case "foreign-cleanup":
				ctx = context.WithValue(ctx, nfqwsProbeCleanupKey{}, &nfqwsProbeExecution{})
			case "consumer":
				e.consumer = &ManagedNFQWSProbeConsumer{}
			case "resource":
				a.resource = &NFQWSExecutionResource{}
			case "binding":
				a.binding = &NFQWSScopedBinding{}
			case "command":
				a.command.ID = "foreign"
			case "result":
				e.processResult = &nfqws2ManagedProcessLease{}
			case "wait-copy":
				e.processWait = &nfqwsProbeProcessWait{self: w, execution: e}
			case "wait-execution":
				w.execution = &nfqwsProbeExecution{}
			case "wait-command":
				w.intent.Command.ID = "foreign"
			case "wait-root":
				w.root = nil
			case "wait-channel":
				w.done = nil
			case "wait-binding":
				w.intent.LaunchBinding = &NFQWSExecutionBinding{}
			}
			if got := a.initialProbeCleanupWait(ctx, e); (got == w) != (mode == "same") {
				t.Fatal("foreign retained Wait admitted", mode)
			}
			if lease, err := a.acknowledgeInitialProbeCleanup(ctx, e); err == nil || lease.Acknowledged {
				t.Fatal("local associations minted actual cleanup authority", mode)
			}
		})
	}
}

func TestNFQWSProbeInitialCleanupRetainedWaitACK(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("original Linux writer/root descriptor custody")
	}
	for _, mode := range []string{"delayed-same-wait", "deadline", "wait-error", "foreign-marker", "foreign-birth", "foreign-intent"} {
		t.Run(mode, func(t *testing.T) {
			a, intent := nfqws2ManagedRecordFixture(t)
			// Go's t.TempDir child uses 0777 subject to umask; the generic
			// receipt-shape fixture intentionally does not make that ancestor
			// private. Actual ACK validates EVERY ancestor below /tmp.
			if err := os.Chmod(filepath.Dir(a.ConfigPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := nfqws2ManagedObservationPath(filepath.Join(a.StateRoot, nfqws2LeaseFile)); err != nil {
				t.Fatal("original protected ACK fixture path", err)
			}
			_, binding, _, _ := nfqws2ManagedStartFixture(t)
			binding.CommandSHA256 = intent.CommandSHA256
			intent.LaunchBinding = &binding
			terminal := nfqws2ManagedModelTerminal(intent)
			terminal.Acknowledged = false
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			target, err := restorejournal.OpenFileTarget(filepath.Join(a.StateRoot, nfqws2LeaseFile))
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			root, err := newNFQWSProbeProcessRoot(ctx, a.StateRoot, target)
			if err != nil {
				t.Fatal(err)
			}
			defer root.close()
			image, err := nfqws2ManagedLeaseImage(terminal)
			if err != nil {
				t.Fatal(err)
			}
			if err := target.CompareAndSwap(ctx, restorejournal.Image{}, image); err != nil {
				t.Fatal(err)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			e := &nfqwsProbeExecution{command: intent.Command, resource: &NFQWSExecutionResource{binding: binding}}
			e.self = e
			command := exec.Command("never-started-sole-wait-model")
			process := &os.Process{Pid: terminal.Receipt.PID}
			command.Process = process
			w := &nfqwsProbeProcessWait{execution: e, command: command, process: process, intent: intent, root: root, birthKnown: true, birth: components.NFQWSSupervisionIdentity{PID: terminal.Receipt.PID, Group: terminal.Receipt.Group, Start: terminal.Receipt.Start, BootID: terminal.Receipt.BootID}, done: make(chan struct{})}
			w.self, e.processWait = w, w
			waitError := errors.New("original sole Wait failed")
			switch mode {
			case "deadline":
				var cancelShort context.CancelFunc
				ctx, cancelShort = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancelShort()
			case "wait-error":
				w.complete(waitError)
			case "foreign-marker":
				path := filepath.Join(a.StateRoot, root.markerName)
				if err := os.WriteFile(path+".replacement", root.markerBytes, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".replacement", path); err != nil {
					t.Fatal(err)
				}
				w.complete(nil)
			case "foreign-birth":
				w.birth.Start = "201"
				w.complete(nil)
			case "foreign-intent":
				w.intent.Command.ID = "foreign"
				w.complete(nil)
			default:
				done := make(chan struct{})
				go func() { time.Sleep(10 * time.Millisecond); w.complete(nil); close(done) }()
				defer func() { <-done }()
			}
			got, err := w.acknowledge(ctx)
			if (err == nil && got.Acknowledged) != (mode == "delayed-same-wait") {
				t.Fatal("same Wait/foreign outcome mismatch", mode, err)
			}
			if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("existing cleanup deadline lost", err)
			}
			if mode == "wait-error" && !errors.Is(err, waitError) {
				t.Fatal("sole Wait failure lost", err)
			}
			stored, err := restorejournal.ReadFileImage(context.Background(), filepath.Join(a.StateRoot, nfqws2LeaseFile))
			if err != nil {
				t.Fatal(err)
			}
			readback, err := nfqws2DecodeManagedLease(stored, a.StateRoot, intent.Owner)
			if err != nil || readback.Acknowledged != (mode == "delayed-same-wait") {
				t.Fatal("foreign/canceled Wait altered ACK", mode, err)
			}
		})
	}
}

func TestNFQWSProbeInitialCleanupNeverClearsUnknownEvidence(t *testing.T) {
	for _, original := range []error{nil, context.Canceled, errors.Join(ErrNFQWSManagedProcessUnknown, context.Canceled), ErrPolicyAdditionUnknown} {
		retained := errors.Join(original, ErrNFQWSManagedProcessUnknown)
		if nfqwsExecutionOnlyCanceled(retained, 0) || nfqwsProbeOnlyPending(retained, 0) || !errors.Is(retained, ErrNFQWSManagedProcessUnknown) {
			t.Fatal("physical cleanup converted unknown into successful evidence", original)
		}
		if original != nil && !errors.Is(retained, original) {
			t.Fatal("original failure lost")
		}
	}
}
