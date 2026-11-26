package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDomainPriorFileObservationRevokesContextAndKeepsClosingBytes(t *testing.T) {
	for _, mode := range []string{"clean", "body-error", "mutate-restored-time", "cancel", "panic"} {
		t.Run(mode, func(t *testing.T) {
			p, ctx, cancel := domainPriorFileResourceModel(t)
			defer cancel()
			var saved context.Context
			var retained *domainTCPSuccessorRead
			run := func() (err error) {
				defer func() {
					if recovered := recover(); recovered != nil {
						if mode != "panic" {
							panic(recovered)
						}
						err = errors.New("expected panic")
					}
				}()
				return p.observeOriginalPriorFiles(ctx, false, func(observed context.Context, files *xrayDomainTCPFileObservation) error {
					saved = observed
					if observed == ctx || !domainTCPHasPriorRead(observed) || files.current(observed, p) != nil {
						t.Fatal("standalone comparison did not bind its exact original file scope")
					}
					var err error
					retained, err = p.scope.domainSuccessor.originalSuccessorRead(observed)
					if err != nil || retained == nil || retained.files != files || retained.priorRead == nil || !retained.priorRead.contextual {
						t.Fatal("nested counterfactual read did not receive the same typed file loan", err)
					}
					switch mode {
					case "body-error":
						return errors.New("body refused")
					case "cancel":
						cancel()
					case "panic":
						panic("expected panic")
					case "mutate-restored-time":
						e := p.executable
						data, err := os.ReadFile(e.path)
						if err != nil {
							return err
						}
						data[len(data)-1] ^= 1
						if err := os.WriteFile(e.path, data, 0700); err != nil {
							return err
						}
						return os.Chtimes(e.path, e.info.ModTime(), e.info.ModTime())
					}
					return nil
				})
			}
			err := run()
			if (err == nil) != (mode == "clean") {
				t.Fatalf("closing %s: %v", mode, err)
			}
			if saved == nil || !errors.Is(saved.Err(), context.Canceled) || retained == nil || retained.rootCurrent(saved) == nil {
				t.Fatal("file loan/context escaped its synchronous comparison")
			}
			if _, err := p.scope.domainSuccessor.originalSuccessorRead(saved); err == nil {
				t.Fatal("escaped context rebound a successor read")
			}
			if retained.priorRead.bytes.active || !retained.priorRead.bytes.image.lease.closed.Load() {
				t.Fatal("closing did not revoke and release the authenticated image")
			}
		})
	}
}

func TestDomainPriorFileObservationRefusesMixedAndForeignContext(t *testing.T) {
	p, ctx, cancel := domainPriorFileResourceModel(t)
	defer cancel()
	err := p.observeOriginalPriorFiles(ctx, false, func(observed context.Context, _ *xrayDomainTCPFileObservation) error {
		for _, key := range []any{struct{}{}, domainTCPPreAddKey{}, domainTCPGuardReadKey{}, domainTCPBaselineCleanupKey{}, domainTCPCaptureCleanupKey{}, domainTCPFailureCleanupKey{}} {
			foreign := context.WithValue(observed, key, true)
			if read, err := p.scope.domainSuccessor.originalSuccessorRead(foreign); err == nil || read != nil {
				t.Fatal("mixed/foreign context consumed a prior loan", key)
			}
			if err := p.observeOriginalPriorFiles(foreign, false, func(context.Context, *xrayDomainTCPFileObservation) error {
				t.Fatal("present stale key silently took fallback")
				return nil
			}); err == nil {
				t.Fatal("nested read accepted a foreign present key", key)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{true, "foreign", (*domainTCPPriorReadLoan)(nil), &domainTCPPriorReadLoan{}} {
		foreign := context.WithValue(ctx, domainTCPPriorReadKey{}, value)
		if read, err := p.scope.domainSuccessor.originalSuccessorRead(foreign); err == nil || read != nil {
			t.Fatal("unowned prior context admitted a read", value)
		}
	}
}

func TestDomainPriorFileObservationCannotAdmitEffectCleanupOrPublication(t *testing.T) {
	p, ctx, cancel := domainPriorFileResourceModel(t)
	defer cancel()
	check := func(observed context.Context) {
		t.Helper()
		owner := &DomainTCPOriginalScope{}
		owner.self = owner
		if run, err := owner.beginDomainTCPRun(observed, p); err == nil || run != nil || owner.run != nil || owner.process != nil {
			t.Fatal("readonly context reserved a native Run")
		}
		if err := owner.WithCapture(observed, DomainPolicyTCPCaptureSpec{}, nil, func(context.Context) error { t.Fatal("readonly context published capture"); return nil }); err == nil {
			t.Fatal("readonly context entered capture publication")
		}
		if err := owner.PrepareSyntheticCapture(observed, nil, nil); err == nil {
			t.Fatal("readonly context entered capture preparation")
		}
		if review, err := p.cleanupReview(observed); err == nil || review != nil {
			t.Fatal("readonly context borrowed cleanup authority")
		}
		if err := p.scope.domainSuccessor.publishFrame(observed, nil, nil); err == nil {
			t.Fatal("readonly context entered journal publication")
		}
		if err := domainTCPDirectForwardContext(observed); err == nil {
			t.Fatal("readonly context admitted DIRECT forwarding")
		}
		capture := &domainTCPCaptureEffectRunner{resource: &domainTCPCaptureExecutionResource{}}
		baseline := &syntheticBaselineEffectRunner{resource: &syntheticBaselineExecutionResource{}}
		baseline.resource.self = baseline.resource
		for _, runner := range []interface {
			Run(context.Context, string, ...string) ([]byte, error)
			WithStart(context.Context, string, []string, string, func() error) error
		}{capture, baseline} {
			if _, err := runner.Run(observed, "iptables", "-A"); err == nil {
				t.Fatal("readonly context ran a network effect")
			}
			if err := runner.WithStart(observed, "iptables", nil, "", func() error { t.Fatal("readonly context reached Start"); return nil }); err == nil {
				t.Fatal("readonly context admitted a network effect")
			}
		}
	}
	var saved context.Context
	err := p.observeOriginalPriorFiles(ctx, false, func(observed context.Context, _ *xrayDomainTCPFileObservation) error {
		saved = observed
		check(observed)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check(saved)
	// Removing cancellation cannot turn the retained typed marker into an
	// independent Start, cleanup or publication admission either.
	check(context.WithoutCancel(saved))
}

func TestDomainPriorPreparationObservationRefusesMissingSources(t *testing.T) {
	for _, missing := range []string{"capture", "backend", "process"} {
		t.Run(missing, func(t *testing.T) {
			r := &domainTCPCaptureExecutionResource{capture: &DomainPolicyTCPCapture{}, backend: &BackendInventory{}, process: &XrayDomainTCPExecutionResource{}}
			r.self = r
			switch missing {
			case "capture":
				r.capture = nil
			case "backend":
				r.backend = nil
			case "process":
				r.process = nil
			}
			if err := r.observePreparationFiles(context.Background(), false, func(context.Context, *xrayDomainTCPFileObservation) error {
				t.Fatal("missing original source reached observation callback")
				return nil
			}); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
				t.Fatal("missing source was not refused", missing, err)
			}
		})
	}
}
