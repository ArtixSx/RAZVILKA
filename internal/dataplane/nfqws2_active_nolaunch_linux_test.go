//go:build linux

package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNFQWSProducerDefiniteNoLaunchComesFromActualEntry(t *testing.T) {
	for _, kind := range []string{"expired-deadline", "cancelled-panel", "invalid-admission", "foreign-execution", "foreign-command"} {
		t.Run(kind, func(t *testing.T) {
			command, spec, binding := nfqws2ActiveCommandFixture(t)
			command.ActivationDeadline = time.Now().Add(-time.Second).UTC()
			spec.CommandSHA256 = nfqws2ActiveCommandDigest(command)
			binding.CommandSHA256 = spec.CommandSHA256
			a := &NFQWS2Adapter{StateRoot: command.StateRoot}
			e := &nfqws2ActiveExecution{launchInvoked: true}
			e.self = e
			e.material = &NFQWSActiveMaterial{adapter: a, command: command}
			a.activeExecution = e
			calls := 0
			callback := func(context.Context, NFQWSExecutionBinding) error {
				calls++
				t.Error("producer reached effect callback")
				return ErrNFQWSScopedOwner
			}
			with := func(context.Context, NFQWSExecutionBinding, func() error) error {
				calls++
				t.Error("producer reached start/transfer callback")
				return ErrNFQWSScopedOwner
			}
			admission := nfqws2ActiveProcessAdmission{execution: e, Binding: binding, Spec: spec, Provider: &netidentity.Provider{}, BeforeStart: callback, Current: callback, WithStart: with, WithTransfer: with,
				Prepared: func(context.Context, NFQWSExecutionBinding, NFQWSActiveObservation) error {
					calls++
					return ErrNFQWSScopedOwner
				},
				PublishTransferACK: func(context.Context, NFQWSActiveObservation) error { calls++; return ErrNFQWSScopedOwner }}
			// Expiry is deliberately allowed by structural metadata admission;
			// the real activation-context leaf must reject it after entry.
			if !admission.valid(command) {
				t.Fatal("past deadline failed structural admission")
			}
			panel := context.Background()
			switch kind {
			case "cancelled-panel":
				var cancel context.CancelFunc
				panel, cancel = context.WithCancel(panel)
				cancel()
			case "invalid-admission":
				admission.BeforeStart = nil
			case "foreign-execution":
				foreign := &nfqws2ActiveExecution{material: e.material, launchInvoked: true}
				foreign.self = foreign
				admission.execution = foreign
			case "foreign-command":
				e.material.command = command.clone()
				e.material.command.ActivationDeadline = command.ActivationDeadline.Add(-time.Second)
			}
			p, err := a.startPreparedNFQWSProcess(context.Background(), panel, command, nil, admission)
			if err == nil || p != nil || calls != 0 || a.activeProcess != nil {
				t.Fatalf("refusal acquired effects: %v calls=%d", err, calls)
			}
			if _, statErr := os.Lstat(filepath.Join(command.StateRoot, nfqws2LeaseFile)); !os.IsNotExist(statErr) {
				t.Fatalf("producer created intent: %v", statErr)
			}
			// Locking after return also checks that the producer's deferred issuer
			// released the execution mutex before its caller consumes completion.
			e.mu.Lock()
			issued := e.producerUnlaunched()
			e.mu.Unlock()
			want := kind == "expired-deadline" || kind == "cancelled-panel"
			if issued != want || (admission.execution != e && admission.execution.noLaunch != nil) {
				t.Fatalf("completion issued=%t want=%t", issued, want)
			}
			if want {
				stage := "activation-context"
				if kind == "cancelled-panel" {
					stage = "panel-lifetime"
				}
				if !strings.Contains(err.Error(), "StartPrepared."+stage) || e.noLaunch.execution != e || e.noLaunch.command != nfqws2ActiveCommandDigest(command) {
					t.Fatalf("producer completion/error mismatch: %v", err)
				}
			}
		})
	}
}
