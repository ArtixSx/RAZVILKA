package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type ordinaryObservationModel struct {
	facts      map[int]bootstrapControllerFact
	reads      int
	metadata   int
	artifacts  int
	clears     atomic.Int32
	checkError error
}

func ordinaryObservationFixture(t *testing.T, joined bool) (ordinaryObservationSource, *ordinaryObservationModel) {
	t.Helper()
	review, record, identity, command, facts := ordinaryRoleFixture(t)
	m := &ordinaryObservationModel{facts: map[int]bootstrapControllerFact{}}
	for _, fact := range facts {
		m.facts[fact.Process.PID] = fact
	}
	caller := command.DirectPID
	if joined {
		caller = command.Supervisor.PID
	}
	source := ordinaryObservationSource{review: review, record: record, identity: identity, command: command, caller: caller, joined: joined}
	source.read = func(pid int) (bootstrapControllerFact, error) {
		m.reads++
		fact, ok := m.facts[pid]
		if !ok {
			return fact, ErrFileProtocol
		}
		fact.Args = append([]string(nil), fact.Args...)
		return fact, nil
	}
	source.check = func(ctx context.Context, artifacts bool) error {
		m.metadata++
		if artifacts {
			m.artifacts++
		}
		return errors.Join(ctx.Err(), m.checkError)
	}
	source.clear = func() { m.clears.Add(1) }
	return source, m
}

// Real aggregate code with modeled controller/metadata leaves. A read counter
// is source-derived flow, never measured native performance or role proof.
func TestOrdinaryObservationUniqueGroupAndFreshPeerBookends(t *testing.T) {
	for _, joined := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "joined"}[joined], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var escaped *OrdinaryInstallerControllerObservation
			for invocation := 0; invocation < 2; invocation++ {
				source, m := ordinaryObservationFixture(t, joined)
				peers := []int{source.identity.Process.PID, source.command.Supervisor.PID}
				if joined {
					peers = peers[:1]
					delete(m.facts, source.command.DirectPID) // Actual join cannot revive this child.
				}
				var held context.Context
				err := runOrdinaryControllerObservation(ctx, source, func(c context.Context, o *OrdinaryInstallerControllerObservation) error {
					if o == escaped {
						t.Fatal("session reused between observations")
					}
					held, escaped = c, o
					for sweep := 0; sweep < 2; sweep++ {
						for _, pid := range peers {
							for bookend := 0; bookend < 2; bookend++ {
								if err := o.VerifyPeer(c, pid); err != nil {
									return err
								}
							}
						}
					}
					return nil
				})
				wantReads := 14 // 28 executable occurrences through controllerAt.
				wantMetadata := 19
				if joined {
					wantReads, wantMetadata = 8, 11 // 16 executable occurrences.
				}
				if err != nil || m.reads != wantReads || m.metadata != wantMetadata || m.artifacts != 1 || m.clears.Load() != 1 {
					t.Fatal("full group/peer/metadata closing was skipped", m.reads, m.metadata, m.artifacts, err)
				}
				if escaped.VerifyPeer(held, peers[0]) == nil || escaped.members != nil || escaped.source.read != nil {
					t.Fatal("escaped session retained readable facts")
				}
			}
		})
	}
}

func TestOrdinaryObservationPoisonAndMandatoryClosing(t *testing.T) {
	for _, change := range []string{"same-pid-exec", "bytes", "birth", "parent", "argv", "receipt", "foreign-context", "self-peer", "foreign-pid", "copied", "cancel", "deadline", "closing-fact", "closing-error", "callback-error", "callback-and-closing", "clear-cancel"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			source, m := ordinaryObservationFixture(t, false)
			cause := errors.New("modeled original boundary")
			callbackCause := errors.New("modeled original callback")
			originalCheck := source.check
			source.check = func(c context.Context, artifacts bool) error {
				if artifacts && change == "closing-fact" {
					fact := m.facts[20]
					fact.Parent++
					m.facts[20] = fact
				}
				if artifacts && (change == "closing-error" || change == "callback-and-closing") {
					m.checkError = cause
				}
				return originalCheck(c, artifacts)
			}
			if change == "clear-cancel" {
				source.clear = func() { m.clears.Add(1); cancel() }
			}
			var peerErr error
			err := runOrdinaryControllerObservation(ctx, source, func(c context.Context, o *OrdinaryInstallerControllerObservation) error {
				fact := m.facts[20]
				switch change {
				case "same-pid-exec":
					fact.Process.Inode++ // PID and birth remain exactly the same.
				case "bytes":
					fact.Process.ExecutableSHA256 = "changed"
				case "birth":
					fact.Process.Start = "changed"
				case "parent":
					fact.Parent++ // Still a valid helper role, but a different fact.
				case "argv":
					fact.Args = append([]string(nil), fact.Args...)
					fact.Args[0] = "other-name" // Role classifier alone still accepts it.
				case "receipt":
					m.checkError = cause
				case "cancel":
					cancel()
				case "callback-error":
					return cause
				case "callback-and-closing":
					return callbackCause
				case "closing-fact", "closing-error", "clear-cancel":
					return nil
				}
				m.facts[20] = fact
				peerContext, peerPID := c, 20
				if change == "foreign-context" {
					peerContext = ctx // Same deadline alone is not the source context.
				}
				if change == "deadline" {
					var stop context.CancelFunc
					peerContext, stop = context.WithDeadline(c, time.Now().Add(-time.Millisecond))
					defer stop()
				}
				if change == "self-peer" {
					peerPID = source.caller
				}
				if change == "foreign-pid" {
					peerPID = 99
				}
				if change == "copied" {
					copy := &OrdinaryInstallerControllerObservation{self: o, original: ctx, deadline: o.deadline}
					peerErr = copy.VerifyPeer(c, peerPID)
				} else {
					peerErr = o.VerifyPeer(peerContext, peerPID)
				}
				if peerErr == nil || o.VerifyPeer(c, 22) == nil {
					t.Fatal("failed peer did not poison the original session")
				}
				return nil // Even an ignored peer failure cannot grant success.
			})
			if err == nil || m.artifacts != 1 || m.clears.Load() != 1 {
				t.Fatal("failure escaped mandatory group closing/cleanup", change, err)
			}
			if (change == "receipt" || change == "closing-error" || change == "callback-error" || change == "callback-and-closing") && !errors.Is(err, cause) {
				t.Fatal("original callback/closing cause was lost")
			}
			if change == "callback-and-closing" && !errors.Is(err, callbackCause) {
				t.Fatal("callback failure was lost behind closing failure")
			}
			if (change == "cancel" || change == "clear-cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("expired context was revived after closing/clear")
			}
			if change == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("expired peer deadline was lost")
			}
		})
	}
}

func TestOrdinaryObservationPartialOpenAndPanicCleanup(t *testing.T) {
	for _, mode := range []string{"partial-open", "panic"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		source, m := ordinaryObservationFixture(t, false)
		cause := errors.New("original opening/panic")
		if mode == "partial-open" {
			read := source.read
			source.read = func(pid int) (bootstrapControllerFact, error) {
				if pid == 22 {
					return bootstrapControllerFact{}, cause
				}
				return read(pid)
			}
		}
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			err := runOrdinaryControllerObservation(ctx, source, func(context.Context, *OrdinaryInstallerControllerObservation) error {
				if mode == "partial-open" {
					t.Fatal("partially observed group invoked callback")
				}
				panic(cause)
			})
			if !errors.Is(err, cause) {
				t.Fatal("opening failure was lost")
			}
		}()
		cancel()
		if m.clears.Load() != 1 || m.artifacts != 1 || mode == "panic" && recovered != cause {
			t.Fatal("partial opening/panic skipped closing or swallowed panic")
		}
	}
}

func TestOrdinaryObservationConcurrentEscapeRefusesAndCleans(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	source, m := ordinaryObservationFixture(t, false)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	read := source.read
	source.read = func(pid int) (bootstrapControllerFact, error) {
		if m.reads == 3 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return bootstrapControllerFact{}, ctx.Err()
			}
		}
		return read(pid)
	}
	err := runOrdinaryControllerObservation(ctx, source, func(c context.Context, o *OrdinaryInstallerControllerObservation) error {
		go func() { done <- o.VerifyPeer(c, 20) }()
		select {
		case <-started:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil // Escaping a still-active reader cannot grant success.
	})
	close(release)
	if peerErr := <-done; err == nil || peerErr == nil || m.clears.Load() != 1 {
		t.Fatal("concurrent escape granted success or raced cleanup", err, peerErr)
	}
}

func TestOrdinaryObservationClosingReverifiesActualArtifacts(t *testing.T) {
	for _, kind := range []string{"release", "migrated-config"} {
		t.Run(kind, func(t *testing.T) {
			a, u, review := fileAdapterFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, _, err := a.load(ctx, review.ID); err != nil {
				t.Fatal(err)
			}
			source, m := ordinaryObservationFixture(t, false)
			check := source.check
			source.check = func(c context.Context, artifacts bool) error {
				if artifacts {
					if _, _, err := a.load(c, review.ID); err != nil {
						m.artifacts++
						return ordinaryInstallerRoleAt("header-closing", err)
					}
				}
				return check(c, artifacts)
			}
			err := runOrdinaryControllerObservation(ctx, source, func(context.Context, *OrdinaryInstallerControllerObservation) error {
				path := filepath.Join(u.Directory, review.ID, "bundle", "dist", u.record.Job.Release.Binary.Name)
				if kind == "migrated-config" {
					path = filepath.Join(u.Directory, review.ID, "staged", "config.json")
				}
				if err := os.WriteFile(path, []byte("changed while observing\n"), 0600); err != nil {
					t.Fatal(err)
				}
				// Header-only reads still accept the actual unchanged headers.
				if _, _, err := a.loadHeader(ctx, review.ID); err != nil {
					t.Fatal(err)
				}
				return nil
			})
			if err == nil || OrdinaryInstallerControllerFailureStage(err) != "header-closing" || m.artifacts != 1 || m.clears.Load() != 1 {
				t.Fatal("persistent actual artifact change escaped full closing")
			}
		})
	}
}

func TestOrdinaryObservationPublicAPIHasNoModelAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := false
	if err := (&SelfUpdateFileAdapter{}).WithOrdinaryInstallerControllerObservation(ctx, "0123456789abcdef0123456789abcdef", func(context.Context, *OrdinaryInstallerControllerObservation) error { called = true; return nil }); !errors.Is(err, ErrOrdinaryInstallerControllerRole) || called {
		t.Fatal("public callback or zero adapter minted an ordinary group")
	}
	if (&OrdinaryInstallerControllerObservation{}).VerifyPeer(ctx, 20) == nil {
		t.Fatal("zero reader supplied a peer role")
	}
}
