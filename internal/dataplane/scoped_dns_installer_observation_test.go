package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// The actual scanner/files/kernel/provider orchestration uses a private group
// model. No real installer group, hardware or DNS runtime is accepted here.
func TestScopedDNSOrdinaryObservationSpansBothScansAndProviderClosing(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	for _, pid := range []int{102, 103} {
		f.process(t, pid, "other")
		writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, map[int]string{102: "102", 103: "103"}[pid], "cmdline"), []byte("other\x00self-update-command-helper\x00"))
	}
	trace := []string{}
	groups, peers := 0, 0
	var callbackContext context.Context
	provider := f.proof.withCurrent
	f.proof.withCurrent = func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
		trace = append(trace, "identity-opening")
		c, cancel := context.WithCancel(ctx)
		callbackContext = c
		err := provider(c, use)
		cancel() // Group closing must use its original DNS ctx, not this ctx.
		trace = append(trace, "identity-closing")
		return err
	}
	f.proof.installerPeerCheck = func(context.Context, int) error {
		t.Fatal("old per-peer full-group reader was used")
		return nil
	}
	f.proof.installerObservation = func(ctx context.Context, use func(context.Context, func(context.Context, int) error) error) error {
		groups++
		deadline, finite := ctx.Deadline()
		if !finite || time.Until(deadline) > 2*time.Second || ctx.Err() != nil {
			t.Fatal("observation expanded the original DNS budget")
		}
		trace = append(trace, "group-opening")
		err := use(ctx, func(c context.Context, pid int) error {
			if c != callbackContext || c.Err() != nil || pid != 102 && pid != 103 {
				return ErrScopedDNSRuntimeInactive
			}
			peers++
			return nil
		})
		if ctx.Err() != nil || callbackContext.Err() != context.Canceled {
			t.Fatal("closing borrowed cancelled provider context or revived source")
		}
		trace = append(trace, "group-closing")
		return err
	}
	for invocation := 0; invocation < 2; invocation++ {
		if err := f.verify(); err != nil {
			t.Fatal(err)
		}
	}
	wantTrace := []string{"group-opening", "identity-opening", "identity-closing", "group-closing", "group-opening", "identity-opening", "identity-closing", "group-closing"}
	if groups != 2 || peers != 16 || f.kernelCalls != 2 || !reflect.DeepEqual(trace, wantTrace) {
		t.Fatal("group/peer/provider/kernel observations skipped or cached", groups, peers, trace)
	}
}

func TestScopedDNSOrdinaryObservationCannotGrantAfterClosingFailure(t *testing.T) {
	for _, failure := range []string{"opening", "closing", "callback-and-closing", "provider-closing", "final-intent", "final-source", "nil-peer", "skipped-callback", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			f.process(t, 102, "other")
			writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "102", "cmdline"), []byte("other\x00self-update-command-helper\x00"))
			closingCause, callbackCause := errors.New("original group closing"), errors.New("original callback/provider")
			closed := false
			if failure == "callback-and-closing" {
				f.a.InactivityKernelCheck = func(context.Context, netidentity.Identity) error { return callbackCause }
			}
			if failure == "provider-closing" {
				provider := f.proof.withCurrent
				f.proof.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					return errors.Join(provider(c, use), callbackCause)
				}
			}
			f.proof.installerObservation = func(ctx context.Context, use func(context.Context, func(context.Context, int) error) error) (result error) {
				if failure == "opening" {
					return closingCause
				}
				if failure == "skipped-callback" {
					return nil
				}
				defer func() {
					closed = true
					if failure == "closing" || failure == "callback-and-closing" {
						result = errors.Join(result, closingCause)
					}
				}()
				var peer func(context.Context, int) error = func(c context.Context, pid int) error { return c.Err() }
				if failure == "nil-peer" {
					peer = nil
				}
				if failure == "cancel" {
					c, cancel := context.WithCancel(ctx)
					cancel()
					return use(c, peer)
				}
				result = use(ctx, peer)
				if failure == "final-intent" {
					writeDNSInactiveFixture(t, f.a.InactivitySettingsPath, []byte("changed during group closing"))
				}
				if failure == "final-source" {
					f.a.StateRoot += "-changed"
				}
				return result
			}
			err := f.verify()
			if err == nil || !errors.Is(err, ErrScopedDNSRuntimeInactive) || failure != "opening" && failure != "skipped-callback" && !closed {
				t.Fatal("aggregate failure bypassed closing/final guard", failure)
			}
			if (failure == "closing" || failure == "callback-and-closing") && !errors.Is(err, closingCause) || (failure == "callback-and-closing" || failure == "provider-closing") && !errors.Is(err, callbackCause) {
				t.Fatal("original callback or closing cause was lost")
			}
		})
	}
}

// Actual context and lifecycle mutex, with the existing private inventory
// fixture. Cancellation occurs after final checkLocal's opening ctx check,
// while its real epoch read is waiting on the mutex; no sleep selects the race.
func TestScopedDNSOrdinaryObservationFinalMutexCancellationRefuses(t *testing.T) {
	f := newScopedDNSInactiveFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	locked, started, finished := make(chan struct{}), make(chan string, 1), make(chan struct{})
	result := make(chan error, 1)
	var held atomic.Bool
	f.proof.installerObservation = func(ctx context.Context, use func(context.Context, func(context.Context, int) error) error) error {
		err := use(ctx, func(c context.Context, pid int) error { return c.Err() })
		if err != nil {
			return err
		}
		scopedDNSInactiveLifecycle.Lock()
		held.Store(true)
		close(locked)
		return nil
	}
	defer func() {
		cancel()
		if held.Swap(false) {
			scopedDNSInactiveLifecycle.Unlock()
		}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("final epoch observer failed to join")
		}
	}()
	go func() {
		var identity [128]byte
		n := runtime.Stack(identity[:], false)
		fields := strings.Fields(string(identity[:n]))
		started <- fields[1]
		result <- f.a.verifyDNSRuntimeInactive(parent, f.proof)
		close(finished)
	}()
	id := <-started
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("group observation never reached closing")
	}
	// Observe the exact verifier goroutine in the real epoch reader. The held
	// mutex prevents it from returning, and the preceding ctx check has passed.
	wait := time.NewTimer(time.Second)
	defer wait.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	var stacks [64 << 10]byte
	for {
		n := runtime.Stack(stacks[:], true)
		blocked := false
		for _, stack := range strings.Split(string(stacks[:n]), "\n\n") {
			if strings.HasPrefix(stack, "goroutine "+id+" ") && strings.Contains(stack, "scopedDNSInactiveEpoch(") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		select {
		case <-wait.C:
			t.Fatal("final checkLocal did not wait on the held lifecycle mutex")
		case <-tick.C:
		}
	}
	cancel()
	if held.Swap(false) {
		scopedDNSInactiveLifecycle.Unlock()
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrScopedDNSRuntimeInactive) || ScopedDNSRuntimeInactiveStage(err) != "lifecycle-final" {
			t.Fatal("cancelled final epoch read granted success", ScopedDNSRuntimeInactiveStage(err))
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled final observer failed to return")
	}
}
