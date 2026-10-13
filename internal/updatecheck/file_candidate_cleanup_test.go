package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Actual PE/ELF supervisor handle and sole Wait, with model kernel/review
// facts. Native tests separately exercise actual subreaping and /proc.
func candidateCleanupFixture(t *testing.T, held context.Context, a *SelfUpdateFileAdapter, code int) (*candidateStartWait, fileCommandReceipt, func() error) {
	t.Helper()
	worker, wait := ordinaryInstallerActualChild(t, code)
	_, _, _, command, _ := ordinaryInstallerWaitFixture(t, held, a, worker)
	w, err := beginCandidateStartWait(held, a, command.ID, worker, command.Parent, command.Supervisor)
	if err != nil {
		t.Fatal(err)
	}
	ready := command
	ready.Command, ready.State, ready.WaitECHILD = "start-candidate-panel", "runtime-ready", false
	ready.DirectPID = worker.Process.Pid + 100
	ready.Runtime = command.Parent
	ready.Runtime.PID, ready.Runtime.Start, ready.Runtime.Inode = worker.Process.Pid+101, "987", 23
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "razvilka.pid"), []byte(strconv.Itoa(ready.Runtime.PID)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pid, err := captureCandidatePID(directory, ready.Runtime.PID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.rememberReady(held, ready, pid); err != nil {
		pid.close()
		t.Fatal(err)
	}
	final := ready
	final.State, final.Reaped, final.WaitECHILD = "reaped", ready.Reaped+1, true
	return w, final, wait
}

func candidateCompletionIntent(id string) selfupdatejournal.Receipt {
	return selfupdatejournal.Receipt{Schema: selfupdatejournal.Schema, ID: id, Phase: "command-started", Command: "stop-candidate-panel", Index: 6,
		Commands: []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel"}}
}

// Actual supervisor Wait; callbacks model only platform/record checks. This
// cannot mint a native role or authorize a production settlement.
func TestCandidateStoppedCompletionLifetimeAndReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := NewSelfUpdateFileAdapter()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var escaped context.Context
	err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
		w, final, wait := candidateCleanupFixture(t, held, a, 0)
		w.review.AuthorityInstallationID, w.review.AuthoritySequence, w.review.Revision = "cccccccccccccccccccccccccccccccc", 10, 7
		intent := candidateCompletionIntent(id)
		freshChecks := 0
		fresh := func(c context.Context, _ *candidateAbsenceCompletion) error { freshChecks++; return c.Err() }
		observe := func(context.Context, *candidateAbsenceCompletion, func(context.Context, *OrdinaryInstallerControllerObservation) error) error {
			return ErrFileProtocol
		}
		if err := sealCandidateAbsenceCompletion(held, w, final, intent, fresh, observe); err == nil {
			t.Fatal("JSON and no actual Wait created completion")
		}
		w.observeWait(wait())
		if err := executeCandidateCleanup(held, w, final, func() error { return nil }, func(begin func() error) error { return begin() }, func(p *candidatePIDImage) error { return p.root.Remove("razvilka.pid") }); err != nil {
			return err
		}
		if err := sealCandidateAbsenceCompletion(held, w, final, intent, fresh, observe); err != nil {
			return err
		}
		if err := sealCandidateAbsenceCompletion(held, w, final, intent, fresh, observe); err == nil {
			t.Fatal("duplicate completion accepted")
		}
		derived := context.WithValue(held, candidateStoppedReadKey{}, nil)
		if err := a.withCandidateStoppedRead(derived, id, func(context.Context) error { t.Fatal("derived entry accepted"); return nil }); err == nil {
			t.Fatal("derived context opened a session")
		}
		return a.withCandidateStoppedRead(held, id, func(read context.Context) error {
			escaped = read
			child := context.WithValue(read, struct{}{}, "writer observation")
			s, err := candidateStoppedReadFor(child, a, id)
			if err != nil {
				return err
			}
			before := freshChecks
			state, process := w.state, w.process
			w.state = nil
			if _, err := candidateStoppedReadFor(child, a, id); err == nil || freshChecks != before {
				t.Fatal("missing actual Wait state reached platform checks", err)
			}
			w.state, w.process = state, nil
			if _, err := candidateStoppedReadFor(child, a, id); err == nil || freshChecks != before {
				t.Fatal("foreign process handle reached platform checks", err)
			}
			w.process = process
			w.owner.candidate = nil
			if _, err := candidateStoppedReadFor(child, a, id); err == nil || freshChecks != before {
				t.Fatal("detached original slot reached platform checks", err)
			}
			w.owner.candidate = w
			cancelled, revoke := context.WithCancel(child)
			revoke()
			if _, err := candidateStoppedReadFor(cancelled, a, id); err == nil || freshChecks != before {
				t.Fatal("cancelled read reached platform checks", err)
			}
			copySession := candidateStoppedRead{self: s.self, completion: s.completion, original: s.original, deadline: s.deadline}
			copySession.active.Store(true)
			if _, err := candidateStoppedReadFor(context.WithValue(child, candidateStoppedReadKey{}, &copySession), a, id); err == nil {
				t.Fatal("copied session accepted")
			}
			copyCompletion := *s.completion
			if err := copyCompletion.current(child, a, id); err == nil {
				t.Fatal("copied completion accepted")
			}
			restored := intent
			restored.Commands = append(append([]string{}, intent.Commands...), "restore-private-state")
			restored.Rollback, restored.Phase, restored.Command = true, "command-finished", "restore-private-state"
			if err := s.completion.receipt(restored); err != nil {
				return err
			}
			terminal := restored
			terminal.Schema, terminal.Phase, terminal.Command = selfupdatejournal.StoppedSchema, stoppedRollbackState, ""
			binding := selfupdatejournal.StoppedBinding{InstallationID: w.review.AuthorityInstallationID, PreStopSequence: 10, StopSequence: 11, Revision: 7, RequiredReader: selfupdatejournal.StoppedSchema}
			terminal.Stopped = &binding
			if err := s.completion.receipt(terminal); err != nil {
				return err
			}
			for _, change := range []func(*selfupdatejournal.StoppedBinding){
				func(b *selfupdatejournal.StoppedBinding) { b.InstallationID = "dddddddddddddddddddddddddddddddd" },
				func(b *selfupdatejournal.StoppedBinding) { b.PreStopSequence++ },
				func(b *selfupdatejournal.StoppedBinding) { b.StopSequence++ },
				func(b *selfupdatejournal.StoppedBinding) { b.Revision++ },
			} {
				badBinding := binding
				change(&badBinding)
				bad := terminal
				bad.Stopped = &badBinding
				if err := s.completion.receipt(bad); err == nil {
					t.Fatal("unrelated Stop binding accepted")
				}
			}
			for _, change := range []func(*selfupdatejournal.Receipt){
				func(r *selfupdatejournal.Receipt) { r.Phase = "command-started" },
				func(r *selfupdatejournal.Receipt) { r.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
				func(r *selfupdatejournal.Receipt) { r.Rollback = false },
				func(r *selfupdatejournal.Receipt) { r.Index-- },
				func(r *selfupdatejournal.Receipt) { r.Commands = intent.Commands },
				func(r *selfupdatejournal.Receipt) { r.Command = "start-rollback-panel" },
			} {
				bad := restored
				change(&bad)
				if err := s.completion.receipt(bad); err == nil {
					t.Fatal("unrelated/unknown receipt accepted")
				}
			}
			if err := executeCandidateCleanup(held, w, final, func() error { t.Fatal("consumed cleanup check ran"); return nil }, func(func() error) error { return nil }, func(*candidatePIDImage) error { t.Fatal("unlink repeated"); return nil }); err == nil {
				t.Fatal("completion restored effect authority")
			}
			before = freshChecks
			if err := os.WriteFile(filepath.Join(w.pid.directory, "razvilka.pid"), w.pid.data, 0600); err != nil {
				return err
			}
			if _, err := candidateStoppedReadFor(child, a, id); err == nil || freshChecks != before {
				t.Fatal("replacement PID reached fresh completion checks", err)
			}
			if err := os.Remove(filepath.Join(w.pid.directory, "razvilka.pid")); err != nil {
				return err
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidateStoppedReadFor(escaped, a, id); err == nil {
		t.Fatal("session survived H callback exit")
	}
}

func TestCandidateStoppedCompletionClosingRefusalHasNoSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := NewSelfUpdateFileAdapter()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := runOrdinaryInstallerJoinScope(a, ctx, id, func(held context.Context) error {
		w, final, wait := candidateCleanupFixture(t, held, a, 0)
		w.observeWait(wait())
		checks := 0
		err := executeCandidateCleanup(held, w, final, func() error {
			checks++
			if checks == 3 {
				return ErrReviewChanged
			}
			return nil
		}, func(begin func() error) error { return begin() }, func(p *candidatePIDImage) error { return p.root.Remove("razvilka.pid") })
		if !errors.Is(err, ErrReviewChanged) || w.consumed || w.completion != nil {
			t.Fatal("failed closing cleanup created completion", err)
		}
		fresh := func(context.Context, *candidateAbsenceCompletion) error {
			t.Fatal("failed cleanup reached fresh source")
			return nil
		}
		observe := func(context.Context, *candidateAbsenceCompletion, func(context.Context, *OrdinaryInstallerControllerObservation) error) error {
			return nil
		}
		if err := sealCandidateAbsenceCompletion(held, w, final, candidateCompletionIntent(id), fresh, observe); err == nil {
			t.Fatal("absence after failed bookend created completion")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateCleanupRequiresOriginalActualWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := NewSelfUpdateFileAdapter()
	var escaped *candidateStartWait
	var escapedCtx context.Context
	err := runOrdinaryInstallerJoinScope(a, ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", func(held context.Context) error {
		w, final, wait := candidateCleanupFixture(t, held, a, 0)
		escaped, escapedCtx = w, held
		checks, effects := 0, 0
		check := func() error { checks++; return nil }
		admit := func(begin func() error) error { return begin() }
		remove := func(pid *candidatePIDImage) error { effects++; return pid.root.Remove("razvilka.pid") }
		if err := executeCandidateCleanup(held, w, final, check, admit, remove); !errors.Is(err, ErrFileCommandUnsettled) || checks != 0 || effects != 0 {
			t.Fatal("JSON minted cleanup before original Wait", err, checks, effects)
		}
		w.observeWait(wait())
		if err := executeCandidateCleanup(held, w, final, check, admit, remove); err != nil || effects != 1 || checks != 3 {
			t.Fatal("original actual Wait did not complete cleanup", err, checks, effects)
		}
		if err := executeCandidateCleanup(held, w, final, check, admit, remove); err == nil || effects != 1 {
			t.Fatal("consumed source reused", err, effects)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := executeCandidateCleanup(escapedCtx, escaped, fileCommandReceipt{}, func() error { return nil }, func(begin func() error) error { return begin() }, func(*candidatePIDImage) error { t.Fatal("escaped effect"); return nil }); err == nil {
		t.Fatal("source escaped scope")
	}
}

func TestCandidateCleanupEffectIsExactOwnedCompensation(t *testing.T) {
	if !validFileEffect(candidateKnownAbsentPIDEffect) || !validFileEffectAction(candidateKnownAbsentPIDEffect, "stop-owned") {
		t.Fatal("exact cleanup effect refused")
	}
	for _, action := range []string{"start/live", "replace-to-rollback", bootstrapOfflineAction, "read/observe", ""} {
		if validFileEffectAction(candidateKnownAbsentPIDEffect, action) {
			t.Fatal("cleanup borrowed different action", action)
		}
	}
	for _, effect := range []string{"candidate-known-absent-pid-extra", "candidate-known-absent", "candidate-known-absent-pid-../other"} {
		if validFileEffect(effect) {
			t.Fatal("effect scope widened", effect)
		}
	}
}

func TestCandidateCleanupRefusesBrokenProvenanceBeforeEffects(t *testing.T) {
	for _, mode := range []string{"derived", "cancelled", "copy", "wait-failed", "wait-duplicate", "handle-changed", "state-changed", "ready-missing", "runtime-changed", "supervisor-changed", "direct-changed", "not-echild", "cancelled-receipt", "exit-error", "no-runtime-reap"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a := NewSelfUpdateFileAdapter()
			err := runOrdinaryInstallerJoinScope(a, ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", func(held context.Context) error {
				code := 0
				if mode == "wait-failed" {
					code = 7
				}
				w, final, wait := candidateCleanupFixture(t, held, a, code)
				w.observeWait(wait())
				useCtx := held
				switch mode {
				case "derived":
					useCtx = context.WithValue(held, struct{}{}, true)
				case "cancelled":
					cancel()
				case "copy":
					w = &candidateStartWait{self: w, owner: w.owner, joined: w.joined}
				case "wait-duplicate":
					w.observeWait(nil)
				case "handle-changed":
					w.worker.Process = &os.Process{Pid: w.process.Pid}
				case "state-changed":
					w.worker.ProcessState = nil
				case "ready-missing":
					w.ready = fileCommandReceipt{}
				case "runtime-changed":
					final.Runtime.Inode++
				case "supervisor-changed":
					final.Supervisor.Start = "111"
				case "direct-changed":
					final.DirectPID++
				case "not-echild":
					final.WaitECHILD = false
				case "cancelled-receipt":
					final.Cancelled, final.ExitCode = true, 125
				case "exit-error":
					final.ExitCode = 7
				case "no-runtime-reap":
					final.Reaped = w.ready.Reaped
				}
				effects, checks := 0, 0
				err := executeCandidateCleanup(useCtx, w, final, func() error { checks++; return nil }, func(begin func() error) error { return begin() }, func(*candidatePIDImage) error { effects++; return nil })
				if err == nil || effects != 0 || checks != 0 {
					t.Fatal("broken provenance reached effect checks", err, checks, effects)
				}
				return nil
			})
			if mode != "cancelled" && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCandidateCleanupPIDAndAdmissionBookends(t *testing.T) {
	for _, mode := range []string{"already-absent", "replacement", "changed-bytes", "changed-mode", "closing-refusal", "after-remove-refusal", "skipped-admission", "duplicate-admission", "escaped-admission", "concurrent-source"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a := NewSelfUpdateFileAdapter()
			if err := runOrdinaryInstallerJoinScope(a, ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", func(held context.Context) error {
				w, final, wait := candidateCleanupFixture(t, held, a, 0)
				w.observeWait(wait())
				path := filepath.Join(w.pid.directory, "razvilka.pid")
				switch mode {
				case "already-absent":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, w.pid.data, 0600); err != nil {
						t.Fatal(err)
					}
				case "changed-bytes":
					if err := os.WriteFile(path, []byte("123\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "changed-mode":
					if err := os.Chmod(path, 0400); err != nil {
						t.Fatal(err)
					}
				}
				checks, effects, admissions := 0, 0, 0
				var escaped func() error
				check := func() error {
					checks++
					if mode == "closing-refusal" && checks == 2 || mode == "after-remove-refusal" && checks == 3 {
						return ErrReviewChanged
					}
					return nil
				}
				admit := func(begin func() error) error {
					admissions++
					switch mode {
					case "skipped-admission":
						return nil
					case "escaped-admission":
						escaped = begin
						return nil
					case "duplicate-admission":
						if err := begin(); err != nil {
							return err
						}
						_ = begin()
						return nil
					default:
						return begin()
					}
				}
				remove := func(pid *candidatePIDImage) error { effects++; return pid.root.Remove("razvilka.pid") }
				if mode == "concurrent-source" {
					w.mu.Lock()
				}
				err := executeCandidateCleanup(held, w, final, check, admit, remove)
				if mode == "concurrent-source" {
					w.mu.Unlock()
				}
				if mode == "already-absent" {
					if err != nil || effects != 0 || admissions != 0 || checks != 2 {
						t.Fatal("absent PID needed an effect", err, checks, effects, admissions)
					}
				} else {
					wantEffects := 0
					if mode == "duplicate-admission" || mode == "after-remove-refusal" {
						wantEffects = 1
					}
					if err == nil || effects != wantEffects {
						t.Fatal("bad PID/admission completed", err, checks, effects, admissions)
					}
					if w.consumed {
						t.Fatal("refused cleanup consumed original authority")
					}
				}
				if escaped != nil {
					if err := escaped(); err == nil || effects != 0 {
						t.Fatal("admission escaped", err, effects)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
