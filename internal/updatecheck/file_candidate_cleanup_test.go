package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
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
