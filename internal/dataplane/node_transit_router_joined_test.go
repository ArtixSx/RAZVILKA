package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Real private receipt/one-shot lease state; kernel commands and returned
// service failure are MODELED. These tests do not establish service health.
func TestNodeRouterNegativeServicePreservesErrorAndOnlyAcknowledgesJoinedCleanup(t *testing.T) {
	for _, change := range []string{"joined", "unknown-delete", "settlement-refused"} {
		t.Run(change, func(t *testing.T) {
			b, runner, _ := nodeRouterTransitReadbackFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := b.lease.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			serviceErr := errors.New("modeled service predicate failure")
			settleErr := errors.New("modeled original settlement refusal")
			joined, settled := false, false
			registration := nodeTransitRegistration{root: b.root, finished: func() error { joined = true; return nil }, settle: func(c context.Context, s NodeTransitSpec, root, digest string) error {
				if change == "settlement-refused" {
					return settleErr
				}
				if err := b.readback(c, s, root, digest, networkPolicyTransitRemoved); err != nil {
					return err
				}
				settled = true
				return nil
			}}
			if change == "unknown-delete" {
				runner.loseDeleteACK = true
			}
			err := finishRegisteredNodeRouterProbe(ctx, b.spec, registration, b.lease, b, serviceErr)
			if !errors.Is(err, serviceErr) {
				t.Fatal("negative service outcome lost", err)
			}
			if change == "joined" {
				if !joined || !settled || runner.deletes != 1 || len(runner.rules[4]) != 0 {
					t.Fatal("known synchronous cleanup did not join")
				}
			} else if joined || settled {
				t.Fatal("unknown cleanup issued joined ACK")
			}
			if change == "settlement-refused" && !errors.Is(err, settleErr) {
				t.Fatal("settlement exception hidden", err)
			}
		})
	}
}

func TestNodeRouterUnusedJoinedACKRequiresActualOneShotConsume(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "consumed", true: "unknown"}[refuse], func(t *testing.T) {
			b, runner, authority := nodeRouterTransitReadbackUnusedFixture(t, false)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			original := authority.registerErr
			joined := false
			registration := nodeTransitRegistration{root: b.root, cleanupGuard: func(c context.Context) error { return c.Err() }, finished: func() error { joined = true; return nil }, settleUnused: func(c context.Context, s NodeTransitSpec, root, digest string) error {
				return b.readback(c, s, root, digest, networkPolicyTransitUnused)
			}}
			if refuse {
				runner.readErrors[4] = errors.New("modeled unknown rule inventory")
			}
			err := finishRegisteredNodeRouterProbe(ctx, b.spec, registration, b.lease, b, b.unused)
			if !errors.Is(err, original) {
				t.Fatal("before-effects original cause lost", err)
			}
			if joined == refuse || b.unused.claimed.Load() == refuse || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("unused ACK was not bound to original consumed proof", joined, b.unused.claimed.Load())
			}
		})
	}
}
