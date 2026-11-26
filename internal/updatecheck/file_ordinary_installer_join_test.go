package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Native PE on Windows, ELF on Linux when Root runs it. The stdin barrier
// keeps the actual child alive until the parent has captured the launch.
func TestOrdinaryInstallerJoinActualChild(t *testing.T) {
	value := os.Getenv("RAZVILKA_TEST_ORDINARY_JOIN_CHILD")
	if value == "" {
		return
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		os.Exit(99)
	}
	if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		os.Exit(98)
	}
	os.Exit(code)
}

func ordinaryInstallerActualChild(t *testing.T, code int) (*exec.Cmd, func() error) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(binary, "-test.run=^TestOrdinaryInstallerJoinActualChild$")
	worker.Env = append(os.Environ(), "RAZVILKA_TEST_ORDINARY_JOIN_CHILD="+strconv.Itoa(code))
	worker.Stdin = input
	if err := worker.Start(); err != nil {
		input.Close()
		release.Close()
		t.Fatal(err)
	}
	input.Close()
	t.Cleanup(func() {
		release.Close()
		if worker.ProcessState == nil {
			_ = worker.Process.Kill()
			_ = worker.Wait()
		}
	})
	return worker, func() error {
		if _, err := release.Write([]byte{1}); err != nil {
			return err
		}
		release.Close()
		return worker.Wait() // sole original parent Wait, never a receipt PID
	}
}

// Identities/argv/review are model facts; Process, PID and Wait are actual.
// This exercises the private contract and is not production native admission.
func ordinaryInstallerWaitFixture(t *testing.T, ctx context.Context, a *SelfUpdateFileAdapter, worker *exec.Cmd) (fileReview, updateRecord, fileHelperIdentity, fileCommandReceipt, bootstrapControllerFact) {
	t.Helper()
	review, record, identity, command, facts := ordinaryRoleFixture(t)
	o, ok := ctx.Value(ordinaryInstallerJoinKey{}).(*ordinaryInstallerJoin)
	if !ok || o == nil || o.adapter != a {
		t.Fatal("fixture has no original owner")
	}
	review.ID, record.Job.ID, identity.ID, command.ID = o.id, o.id, o.id, o.id
	facts[0].Args[2] = o.id
	identity.Process.PID = os.Getpid()
	command.Parent = identity.Process
	command.Supervisor.PID = worker.Process.Pid
	record.Job.HelperPID = identity.Process.PID
	command.State, command.Reaped, command.WaitECHILD = "reaped", 1, true
	facts[0].Process = identity.Process
	return review, record, identity, command, facts[0]
}

func TestOrdinaryInstallerJoinActualWaitAndFreshAggregate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := NewSelfUpdateFileAdapter()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var escaped context.Context
	err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
		escaped = held
		worker, wait := ordinaryInstallerActualChild(t, 0)
		review, record, identity, command, fact := ordinaryInstallerWaitFixture(t, held, a, worker)
		if command.ID != id {
			t.Fatal("fixture job mismatch", command.ID, id)
		}
		w, err := beginOrdinaryInstallerWait(held, a, id, worker, command.Parent, command.Supervisor)
		if err != nil {
			t.Fatal(err)
		}
		w.observeWait(wait())
		if err := w.complete(held, command); err != nil {
			t.Fatal(err)
		}
		o := w.owner
		reads, closes := 0, 0
		source := ordinaryObservationSource{review: review, record: record, identity: identity, command: command, caller: os.Getpid(), installerJoin: o,
			read: func(pid int) (bootstrapControllerFact, error) {
				reads++
				if pid != os.Getpid() {
					t.Fatal("joined H tried to read dead S/C as live members", pid)
				}
				return fact, nil
			},
			check: func(c context.Context, _ bool) error {
				actual, err := o.joined(c, a, id, os.Getpid())
				if actual != command {
					return ErrOrdinaryInstallerControllerRole
				}
				return err
			}, clear: func() { closes++ }}
		for i := 0; i < 2; i++ {
			if err := runOrdinaryControllerObservation(held, source, func(c context.Context, observation *OrdinaryInstallerControllerObservation) error {
				if len(observation.members) != 1 || observation.members[0].Process != identity.Process {
					t.Fatal("joined H membership expanded", observation.members)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		if reads != 4 || closes != 2 {
			t.Fatal("aggregate cached facts or skipped closing", reads, closes)
		}
		if ordinaryControllerRole(review, record, identity, command, fact) != "" || ordinaryControllerReadRole("ordinary-installer", os.Getpid(), os.Getpid(), true, true) {
			t.Fatal("existing C/S running role was relaxed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	o, _ := escaped.Value(ordinaryInstallerJoinKey{}).(*ordinaryInstallerJoin)
	if _, err := o.joined(escaped, a, id, os.Getpid()); !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
		t.Fatal("escaped owner survived callback", err)
	}
}

func TestOrdinaryInstallerJoinRefusesPrejoinUnknownAndDrift(t *testing.T) {
	for _, mode := range []string{"prejoin", "before-wait", "failed-wait", "cancel", "parent", "supervisor", "cancelled-result", "exit-result", "not-started", "wrong-id", "wrong-adapter", "derived-producer", "second-complete", "concurrent", "copy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a := NewSelfUpdateFileAdapter()
			id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
				o, _ := ordinaryInstallerOwner(held, a, id)
				if mode == "prejoin" {
					_, err := o.joined(held, a, id, os.Getpid())
					return err
				}
				code := 0
				if mode == "failed-wait" {
					code = 17
				}
				worker, wait := ordinaryInstallerActualChild(t, code)
				_, _, _, command, _ := ordinaryInstallerWaitFixture(t, held, a, worker)
				producer := held
				if mode == "derived-producer" {
					producer = context.WithValue(held, struct{}{}, true)
				}
				w, err := beginOrdinaryInstallerWait(producer, a, id, worker, command.Parent, command.Supervisor)
				if err != nil {
					_ = wait()
					return err
				}
				if mode == "before-wait" {
					err := w.complete(held, command)
					w.observeWait(wait())
					return err
				}
				w.observeWait(wait())
				switch mode {
				case "cancel":
					cancel()
				case "parent":
					command.Parent.Start = "999"
				case "supervisor":
					command.Supervisor.Inode++
				case "cancelled-result":
					command.Cancelled, command.ExitCode = true, 125
				case "exit-result":
					command.ExitCode = 1
				case "not-started":
					command.State = "not-started"
				}
				if err := w.complete(held, command); err != nil {
					if mode == "wrong-id" || mode == "wrong-adapter" || mode == "second-complete" || mode == "concurrent" || mode == "copy" {
						t.Fatal("fixture failed before its intended boundary", mode, err)
					}
					return err
				}
				switch mode {
				case "wrong-id":
					_, err = o.joined(held, a, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", os.Getpid())
				case "wrong-adapter":
					_, err = o.joined(held, NewSelfUpdateFileAdapter(), id, os.Getpid())
				case "second-complete":
					err = w.complete(held, command)
				case "concurrent":
					o.mu.Lock()
					_, err = o.joined(held, a, id, os.Getpid())
					o.mu.Unlock()
				case "copy":
					copy := &ordinaryInstallerJoin{self: o, adapter: a, id: id, original: ctx, deadline: o.deadline, wait: w}
					copy.active.Store(true)
					_, err = copy.joined(context.WithValue(held, ordinaryInstallerJoinKey{}, copy), a, id, os.Getpid())
				default:
					t.Fatal("refused branch unexpectedly joined", mode)
				}
				return err
			})
			if !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
				t.Fatal("unknown or changed provenance granted a role", mode, err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause was lost", err)
			}
		})
	}
}

func TestOrdinaryInstallerJoinAggregateRefusesPeersDriftAndCancellation(t *testing.T) {
	for _, mode := range []string{"self-peer", "supervisor-peer", "child-peer", "unknown-peer", "drift", "cancel", "closing-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a := NewSelfUpdateFileAdapter()
			id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			closes := 0
			err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
				worker, wait := ordinaryInstallerActualChild(t, 0)
				review, record, identity, command, fact := ordinaryInstallerWaitFixture(t, held, a, worker)
				w, err := beginOrdinaryInstallerWait(held, a, id, worker, command.Parent, command.Supervisor)
				if err != nil {
					t.Fatal(err)
				}
				w.observeWait(wait())
				if err := w.complete(held, command); err != nil {
					t.Fatal(err)
				}
				callbackDone := false
				source := ordinaryObservationSource{review: review, record: record, identity: identity, command: command, caller: os.Getpid(), installerJoin: w.owner,
					read: func(int) (bootstrapControllerFact, error) {
						fresh := fact
						fresh.Args = append([]string(nil), fact.Args...)
						return fresh, nil
					}, check: func(c context.Context, _ bool) error {
						if callbackDone && mode == "closing-error" {
							return ErrOrdinaryInstallerControllerRole
						}
						_, err := w.owner.joined(c, a, id, os.Getpid())
						return err
					}, clear: func() { closes++ }}
				return runOrdinaryControllerObservation(held, source, func(c context.Context, observation *OrdinaryInstallerControllerObservation) error {
					callbackDone = true
					switch mode {
					case "self-peer":
						return observation.VerifyPeer(c, os.Getpid())
					case "supervisor-peer":
						return observation.VerifyPeer(c, command.Supervisor.PID)
					case "child-peer":
						return observation.VerifyPeer(c, command.DirectPID)
					case "unknown-peer":
						return observation.VerifyPeer(c, 99999)
					case "drift":
						fact.Process.Inode++
					case "cancel":
						cancel()
					}
					return nil
				})
			})
			if err == nil || closes != 1 {
				t.Fatal("H aggregate accepted a peer/drift/late cancellation or missed cleanup", mode, err, closes)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("closing cancellation disappeared", err)
			}
		})
	}
}

func TestOrdinaryInstallerJoinPublicEntryRefusesColdContexts(t *testing.T) {
	a := NewSelfUpdateFileAdapter()
	finite, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cancelled, stop := context.WithCancel(finite)
	stop()
	for _, ctx := range []context.Context{nil, context.Background(), cancelled, finite} {
		called := false
		if err := a.WithOriginalOrdinaryInstallerJoin(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrOrdinaryInstallerControllerRole) || called {
			t.Fatal("cold/non-platform entry reached original owner callback", err, called)
		}
	}
	if adapter, err := OriginalOrdinaryInstallerControllerAdapter(context.WithValue(finite, ordinaryInstallerJoinKey{}, struct{}{}), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil || adapter != nil {
		t.Fatal("present invalid H owner became fallback", adapter, err)
	}
}

func TestOrdinaryInstallerJoinReceiptAndIdentityNeverGrantByThemselves(t *testing.T) {
	review, record, identity, command, facts := ordinaryRoleFixture(t)
	command.State, command.Reaped, command.WaitECHILD = "reaped", 1, true
	if ordinaryJoinedInstallerRole(review, record, identity, command, facts[0]) != "ordinary-installer" {
		t.Fatal("matching pure H identity refused")
	}
	for _, mode := range []string{"legacy", "bootstrap", "reader", "stage", "release", "candidate", "argv", "caller", "parent", "live", "pid-alias"} {
		t.Run(mode, func(t *testing.T) {
			review, record, identity, command, facts := ordinaryRoleFixture(t)
			command.State, command.Reaped, command.WaitECHILD = "reaped", 1, true
			switch mode {
			case "legacy":
				review.OldVersion = "0.19.3"
			case "bootstrap":
				review.Bootstrap = &fileBootstrapBinding{}
			case "reader":
				review.JournalReaders = nil
			case "stage":
				record.Job.Stage = "ready"
			case "release":
				record.Job.Release.Version = "0.20.2"
			case "candidate":
				identity.Process.ExecutableSHA256 = record.Job.Release.Binary.Digest[7:]
			case "argv":
				facts[0].Args = []string{"control.bin", "self-update-command-helper", review.ID}
			case "caller":
				facts[0] = facts[1]
			case "parent":
				command.Parent = identity.OldPanel
			case "live":
				command.State, command.Reaped, command.WaitECHILD = "running", 0, false
			case "pid-alias":
				command.DirectPID = identity.Process.PID
			}
			if ordinaryJoinedInstallerRole(review, record, identity, command, facts[0]) != "" {
				t.Fatal("changed identity granted H role", mode)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := NewSelfUpdateFileAdapter()
	if err := runOrdinaryInstallerJoinScope(a, ctx, review.ID, func(held context.Context) error {
		o, _ := ordinaryInstallerOwner(held, a, review.ID)
		return runOrdinaryControllerObservation(held, ordinaryObservationSource{review: review, record: record, identity: identity, command: command, caller: identity.Process.PID, installerJoin: o,
			read: func(int) (bootstrapControllerFact, error) { return facts[0], nil }, check: func(context.Context, bool) error { return nil }, clear: func() {}},
			func(context.Context, *OrdinaryInstallerControllerObservation) error {
				t.Fatal("JSON-only owner reached callback")
				return nil
			})
	}); !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
		t.Fatal("receipt-only owner was accepted", err)
	}
	base := selfupdatejournal.Receipt{Schema: selfupdatejournal.Schema, ID: review.ID, Phase: "prepared", Commands: []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"}}
	if !ordinaryJoinedInstallReceipt(base, review.ID) {
		t.Fatal("ordinary prepared shape refused")
	}
	for _, mode := range []string{"paired", "installed", "rollback", "before-files", "command", "index", "order"} {
		r := base
		switch mode {
		case "paired":
			r.Schema = selfupdatejournal.PairedSchema
		case "installed":
			r.Phase = "installed"
		case "rollback":
			r.Rollback = true
		case "before-files":
			r.BeforeFiles = true
		case "command":
			r.Command = "quiesce-old-runtime"
		case "index":
			r.Index = 1
		case "order":
			r.Commands = []string{"quiesce-old-runtime", "stop-old-panel", "prepare-private-state"}
		}
		if ordinaryJoinedInstallReceipt(r, review.ID) || !reflect.DeepEqual(base.Commands, []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"}) {
			t.Fatal("non-install phase admitted or fixture mutated", mode)
		}
	}
}
