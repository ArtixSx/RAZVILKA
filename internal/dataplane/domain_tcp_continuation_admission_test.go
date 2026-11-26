package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Lifetime comparison only. This carrier cannot issue any native resource;
// public entry still needs real fleet/guard admission and original old owners.
func TestDomainPoolWriterAdmissionExpiresWithOriginalOperation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	m := New(t.TempDir())
	p := domainTCPProofPlanModel(t)
	s := &executionResourceScope{manager: m, plan: p, ctx: ctx}
	c := &domainTCPGlobalSuccessor{scope: s, request: ctx}
	c.self = c
	a := &domainTCPContinuationAdmission{manager: m, request: ctx, digest: p.Digest, cursor: c}
	a.self = a
	a.active.Store(true)
	if err := a.current(c, ctx); err != nil {
		t.Fatal(err)
	}
	copy := &domainTCPContinuationAdmission{self: a, manager: m, request: ctx, digest: p.Digest, cursor: c}
	copy.active.Store(true)
	if err := copy.current(c, ctx); err == nil {
		t.Fatal("copied writer association admitted")
	}
	if err := a.current(c, context.WithValue(ctx, struct{ child bool }{true}, true)); err == nil {
		t.Fatal("foreign context replaced actual scope writer context")
	}
	a.digest = "changed"
	if err := a.current(c, ctx); err == nil {
		t.Fatal("changed digest borrowed original operation")
	}
	a.digest = p.Digest
	a.cursor = &domainTCPGlobalSuccessor{}
	if err := a.current(c, ctx); err == nil {
		t.Fatal("foreign cursor borrowed original operation")
	}
	a.cursor = c
	a.active.Store(false)
	if err := a.current(c, ctx); err == nil {
		t.Fatal("completed operation retained writer admission")
	}
	a.active.Store(true)
	cancel()
	if err := a.current(c, ctx); err == nil {
		t.Fatal("canceled operation retained writer admission")
	}
}

func TestDomainPoolWriterAdmissionRevokesAfterErrorAndPanic(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			m := New(t.TempDir())
			p := domainTCPProofPlanModel(t)
			prior := &DomainTCPDetachedStandby{}
			prior.self = prior
			var retained *domainTCPContinuationAdmission
			witness := errors.New("original callback failure")
			var result error
			func() {
				defer func() {
					caught := recover()
					if mode == "panic" && caught != witness {
						t.Fatal("original panic changed", caught)
					}
					if mode != "panic" && caught != nil {
						panic(caught)
					}
				}()
				result = withDomainContinuationAdmission(ctx, m, p, prior, func(a *domainTCPContinuationAdmission) error {
					retained = a
					if a.initial(ctx, m, p, prior) != nil {
						t.Fatal("actual local association unavailable inside callback")
					}
					if mode == "panic" {
						panic(witness)
					}
					return witness
				})
			}()
			if retained == nil || retained.active.Load() || retained.initial(ctx, m, p, prior) == nil {
				t.Fatal("callback return retained publication association")
			}
			if mode == "error" && !errors.Is(result, witness) {
				t.Fatal("callback error omitted", result)
			}
		})
	}
}
