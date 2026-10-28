package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type privateNodeTransitCause struct{}

func (*privateNodeTransitCause) Error() string { return "private-endpoint /private/path raw-config" }

func TestNodeTransitPhasePreservesCauseWithoutPublishingPrivateText(t *testing.T) {
	cause := &privateNodeTransitCause{}
	err := nodeTransitPhase("apply-register", errors.Join(ErrNodeTransitUnavailable, nodeTransitPhase("register-manager", errors.Join(ErrNodeTransitUnavailable, cause))))
	var actual *privateNodeTransitCause
	if !errors.Is(err, ErrNodeTransitUnavailable) || !errors.Is(err, cause) || !errors.As(err, &actual) || actual != cause {
		t.Fatal("phase annotation lost typed error identity")
	}
	if got := err.Error(); got != "node transit phase=apply-register; node transit phase=register-manager" || strings.Contains(got, "private") {
		t.Fatal("phase annotation published private cause or lost boundary", got)
	}
	if nodeTransitPhase("register-manager", nil) != nil {
		t.Fatal("annotation turned successful boundary into failure")
	}
}

func TestNodeTransitPhaseBeforeEffectsKeepsUnusedAndRetryFences(t *testing.T) {
	for _, phase := range []string{"register-initial-guard", "register-manager", "register-closing-guard", "preflight-owner", "preflight-presence", "preflight-closing-guard"} {
		t.Run(phase, func(t *testing.T) {
			l, runner, authority := nodeTransitFixture(t)
			cause := &privateNodeTransitCause{}
			register, preflight, guard := l.runtime.register, l.runtime.preflight, l.runtime.guard
			switch phase {
			case "register-initial-guard":
				authority.guardErr = cause
			case "register-manager":
				authority.registerErr = cause
			case "register-closing-guard":
				l.runtime.register = func(c context.Context, spec NodeTransitSpec, root, digest string) error {
					err := register(c, spec, root, digest)
					authority.guardErr = cause
					return err
				}
			case "preflight-owner":
				authority.preflightErr = cause
			case "preflight-presence":
				runner.readErrors[4] = cause
			case "preflight-closing-guard":
				calls := 0
				l.runtime.guard = func(c context.Context, spec NodeTransitSpec) error {
					calls++
					// Registration checks twice, presence twice, then the
					// final preflight guard closes the same observation.
					if calls == 5 {
						return cause
					}
					return guard(c, spec)
				}
			}
			err := l.Apply(context.Background())
			var unused *nodeTransitBeforeEffectsError
			var actual *privateNodeTransitCause
			if !errors.As(err, &unused) || !isNodeTransitBeforeEffects(err) {
				t.Fatal("annotated first refusal lost before-effects/cause identity", err)
			}
			// The numeric policy reader already sanitizes command errors;
			// annotations must preserve that existing sentinel contract too.
			if phase == "preflight-presence" {
				if !errors.Is(err, ErrNodeTransitUnavailable) {
					t.Fatal("presence annotation lost its existing sentinel", err)
				}
			} else if !errors.Is(err, cause) || !errors.As(err, &actual) || actual != cause {
				t.Fatal("annotation lost the original typed cause", err)
			}
			if !strings.Contains(err.Error(), "phase="+phase) || strings.Contains(err.Error(), "private") || runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("wrong phase, private disclosure or effect", err)
			}
			authority.guardErr, authority.registerErr, authority.preflightErr = nil, nil, nil
			runner.readErrors[4] = nil
			l.runtime.register, l.runtime.preflight, l.runtime.guard = register, preflight, guard
			if err := l.VerifyUnused(context.Background()); err != nil {
				t.Fatal("annotated refusal could not prove unused", err)
			}
			if err := unused.consumeUnused(context.Background(), l.spec, l.root, l.digest); err != nil {
				t.Fatal("annotated unused proof was not consumable", err)
			}
			if unused.consumeUnused(context.Background(), l.spec, l.root, l.digest) == nil || l.VerifyUnused(context.Background()) == nil {
				t.Fatal("annotation made unused proof replayable")
			}
			authority.registerErr = cause
			if retry := l.Apply(context.Background()); !errors.Is(retry, cause) || isNodeTransitBeforeEffects(retry) {
				t.Fatal("annotated retry acquired fresh before-effects authority", retry)
			}
			if runner.adds != 0 || runner.deletes != 0 {
				t.Fatal("refusal or unused diagnostic changed kernel effects")
			}
		})
	}
}

func TestNodeTransitPhasePresenceKeepsJoinedActiveGuardPhases(t *testing.T) {
	l, runner, _ := nodeTransitFixture(t)
	guard := l.runtime.guard
	cause := &privateNodeTransitCause{}
	calls := 0
	l.runtime.guard = func(c context.Context, spec NodeTransitSpec) error {
		calls++
		if calls == 3 {
			return errors.Join(ErrNodeTransitUnavailable, nodeTransitPhase("verify-backend-disjoint", nodeTransitPhase("backend-engine", nodeTransitPhase("backend-fd-readlink", cause))))
		}
		return guard(c, spec)
	}
	err := l.Apply(context.Background())
	if !isNodeTransitBeforeEffects(err) || !errors.Is(err, cause) || !errors.Is(err, ErrNodeTransitUnavailable) {
		t.Fatal("joined active presence guard changed refusal identity", err)
	}
	for _, phase := range []string{"apply-early-preflight", "preflight-presence", "verify-backend-disjoint", "backend-engine", "backend-fd-readlink"} {
		if !strings.Contains(err.Error(), "phase="+phase) {
			t.Fatal("joined presence error lost inner phase", phase, err)
		}
	}
	if strings.Contains(err.Error(), "private") || len(err.Error()) > 512 || runner.adds != 0 || runner.deletes != 0 {
		t.Fatal("joined diagnostic leaked data, exceeded bound or reached effects", err)
	}
	l.runtime.guard = guard
	if err := l.VerifyUnused(context.Background()); err != nil {
		t.Fatal("joined active guard refusal lost unused proof", err)
	}
}

func TestNodeTransitPhasePreparedReadbackKeepsRealManagerUnusedSettlement(t *testing.T) {
	f := executionResourceManagerFixture(t)
	cause := &privateNodeTransitCause{}
	err := f.m.WithExecutionResources(f.ctx, f.p, "xray", func(ctx context.Context) error {
		ctx = f.bind(t, ctx)
		owner := f.readback.owner
		f.readback.owner = func(context.Context) error { return cause }
		applyErr := f.lease.Apply(ctx)
		if !errors.Is(applyErr, cause) || !isNodeTransitBeforeEffects(applyErr) || !strings.Contains(applyErr.Error(), "phase=registration-prepared-readback") || strings.Contains(applyErr.Error(), "private") {
			t.Fatal("Manager readback refusal lost phase or authority", applyErr)
		}
		if !errors.As(applyErr, &f.readback.unused) {
			t.Fatal("annotated readback refusal lost its live unused proof")
		}
		f.readback.owner = owner
		if err := f.registration.cleanupGuard(ctx); err != nil {
			return err
		}
		if err := f.lease.VerifyUnused(ctx); err != nil {
			return err
		}
		return f.registration.settleUnused(ctx, f.lease.spec, f.registration.root, f.lease.digest)
	})
	if err != nil || f.runner.adds != 0 || f.runner.deletes != 0 {
		t.Fatal("annotated readback did not retain safe unused settlement", err)
	}
	execution := f.latest(t)
	if len(execution.Resources) != 1 || execution.Resources[0].State != "unused" {
		t.Fatal("annotated refusal changed durable unused outcome", execution.Resources)
	}
}
