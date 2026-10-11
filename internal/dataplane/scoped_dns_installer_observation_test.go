package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
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
