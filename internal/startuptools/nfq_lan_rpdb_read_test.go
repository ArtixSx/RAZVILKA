package startuptools

import (
	"context"
	"errors"
	"testing"
	"time"
)

func nfqRPDBScopeModel(t *testing.T) (*policyRunner, context.Context) {
	l := syntheticDNSLeaseModel(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	deadline, _ := ctx.Deadline()
	o := &toolReadObservation{lease: l, review: l.review, identity: l.identity, digest: l.digest, deadline: deadline, active: true}
	o.self = o
	ctx = context.WithValue(ctx, toolReadObservationKey{}, o)
	o.ctx = ctx
	return &policyRunner{l}, ctx
}

// Scope/sequence models only: no fake kernel result or actual child success.
func TestNFQLANRPDBOriginalScopeSequenceAndRevocation(t *testing.T) {
	r, ctx := nfqRPDBScopeModel(t)
	var escaped context.Context
	err := r.WithOriginalNFQWSLANRPDB(ctx, func(c context.Context) error {
		escaped = c
		s, _ := nfqLANRPDBMarker(c)
		for _, family := range []string{"-4", "-6"} {
			release, err := s.enter(c, r, r.lease.profile.ipAlias, []string{family, "-N", "rule", "show"})
			if err != nil {
				return err
			}
			release()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := r.Run(escaped, r.lease.profile.ipAlias, "-4", "-N", "rule", "show"); err == nil || data != nil {
		t.Fatal("escaped scope accepted", err)
	}
}
func TestNFQLANRPDBRefusesWrongOriginalOrSequence(t *testing.T) {
	for _, kind := range []string{"missing-outer", "malformed", "copied", "foreign-runner", "canceled", "wrong-family", "effect", "empty", "closing-source"} {
		t.Run(kind, func(t *testing.T) {
			r, ctx := nfqRPDBScopeModel(t)
			if kind == "missing-outer" {
				ctx = context.Background()
			}
			err := r.WithOriginalNFQWSLANRPDB(ctx, func(c context.Context) error {
				s, _ := nfqLANRPDBMarker(c)
				runner := r
				args := []string{"-4", "-N", "rule", "show"}
				switch kind {
				case "malformed":
					c = context.WithValue(c, nfqLANRPDBKey{}, true)
				case "copied":
					c = context.WithValue(c, nfqLANRPDBKey{}, &nfqLANRPDBScope{self: s, runner: r, lease: r.lease, ctx: c, active: true})
				case "foreign-runner":
					runner = &policyRunner{r.lease}
				case "canceled":
					var cancel context.CancelFunc
					c, cancel = context.WithCancel(c)
					cancel()
				case "wrong-family":
					args[0] = "-6"
				case "effect":
					args = []string{"-4", "rule", "add", "priority", "1234"}
				case "empty":
					return nil
				case "closing-source":
					o, _ := readObservationMarker(c)
					o.mu.Lock()
					o.active = false
					o.mu.Unlock()
					return errors.New("original body refused")
				}
				_, err := runner.Run(c, r.lease.profile.ipAlias, args...)
				return err
			})
			if err == nil {
				t.Fatal("invalid original scope accepted", kind)
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation cause lost", err)
			}
		})
	}
}
func TestNFQLANRPDBRevokeJoinsReadersAndStockKeepsOldPath(t *testing.T) {
	r, ctx := nfqRPDBScopeModel(t)
	joined := make(chan struct{})
	err := r.WithOriginalNFQWSLANRPDB(ctx, func(c context.Context) error {
		s, _ := nfqLANRPDBMarker(c)
		release, err := s.enter(c, r, r.lease.profile.ipAlias, []string{"-4", "-N", "rule", "show"})
		if err != nil {
			return err
		}
		go func() { <-c.Done(); release(); close(joined) }()
		return errors.New("cancel original reader")
	})
	if err == nil {
		t.Fatal("body error lost")
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("reader not joined")
	}
	r.lease.profile.stock = true
	if err := r.WithOriginalNFQWSLANRPDB(ctx, func(c context.Context) error {
		if c != ctx {
			t.Fatal("stock context changed")
		}
		if _, present := nfqLANRPDBMarker(c); present {
			t.Fatal("stock scope minted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNFQLANRPDBRegistrationRetainsCancellationCause(t *testing.T) {
	r, original := nfqRPDBScopeModel(t)
	ctx, cancel := context.WithCancel(original)
	cancel()
	called := false
	err := r.WithOriginalNFQWSLANRPDB(ctx, func(context.Context) error { called = true; return nil })
	if called || !errors.Is(err, ErrUnknown) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled original registration changed", called, err)
	}
}
