package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestNFQWSProbeWaitCustodyRejectsMissingCopiedAndUnjoinedOwners(t *testing.T) {
	for _, mode := range []string{"pending", "wait-error", "missing-birth", "different-command", "copied"} {
		t.Run(mode, func(t *testing.T) {
			a, intent := nfqws2ManagedRecordFixture(t)
			binding := NFQWSExecutionBinding{SessionID: intent.Command.ID, CommandSHA256: intent.CommandSHA256}
			intent.LaunchBinding = &binding
			e := &nfqwsProbeExecution{command: intent.Command, resource: &NFQWSExecutionResource{binding: binding}}
			e.self = e
			command := exec.Command("never-executed-custody-negative")
			process := &os.Process{Pid: 2000}
			command.Process = process
			w := &nfqwsProbeProcessWait{execution: e, command: command, process: process, intent: intent, birth: components.NFQWSSupervisionIdentity{BootID: intent.Command.Parent.BootID, Start: "200", PID: 2000, Group: 2000}, birthKnown: true, done: make(chan struct{})}
			w.self = w
			e.processWait = w
			waitFailure := errors.New("actual sole Wait failure must remain visible")
			switch mode {
			case "pending":
			case "wait-error":
				w.complete(waitFailure)
			case "missing-birth":
				w.birthKnown = false
				w.complete(nil)
			case "different-command":
				e.command.ID = "different"
				w.complete(nil)
			case "copied":
				original := w
				w = &nfqwsProbeProcessWait{self: original, execution: e, command: command, process: process, done: original.done}
				original.complete(nil)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			lease, err := w.acknowledge(ctx)
			if err == nil || lease.Acknowledged {
				t.Fatal("unowned Wait produced ACK")
			}
			if mode == "wait-error" && !errors.Is(err, waitFailure) {
				t.Fatal("original Wait exception lost", err)
			}
			if _, err := os.Stat(filepath.Join(a.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused custody touched ownership state", err)
			}
		})
	}
}
