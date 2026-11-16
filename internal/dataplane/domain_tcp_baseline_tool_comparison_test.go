package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// The actual file protocol is exercised without fabricating a live process,
// tool lease or Current grant. Native original-owner tests cover that producer.
func TestDomainBaselineToolComparisonClosesFilesAndCallback(t *testing.T) {
	for _, mode := range []string{"clean", "body-error", "closing-error", "swallowed", "zero", "twice", "late", "cancel", "mutation", "extended", "foreign", "recovered-panic"} {
		t.Run(mode, func(t *testing.T) {
			process, ctx := domainFileObservationModel(t)
			ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			bodyFailure, closingFailure := errors.New("body refused"), errors.New("tool closing refused")
			var late func(context.Context) error
			var retained *xrayDomainTCPFileObservation
			var retainedCtx context.Context
			calls := 0
			observe := func(parent context.Context, use func(context.Context) error) error {
				if mode == "recovered-panic" {
					defer func() { _ = recover() }()
				}
				if mode == "zero" || mode == "late" {
					late = use
					return nil
				}
				observed := parent
				if mode == "extended" {
					var release context.CancelFunc
					observed, release = context.WithTimeout(context.WithoutCancel(parent), time.Hour)
					defer release()
				}
				if mode == "foreign" {
					observed = context.WithValue(parent, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
				}
				err := use(observed)
				if mode == "twice" {
					_ = use(observed)
				}
				if mode == "closing-error" {
					return closingFailure
				}
				if mode == "swallowed" {
					return nil
				}
				return err
			}
			err := domainTCPBaselineToolComparison(ctx, observe, func(observed context.Context) error {
				calls++
				retainedCtx = observed
				return process.withFileObservation(observed, func(files *xrayDomainTCPFileObservation) error {
					retained = files
					if mode == "recovered-panic" {
						panic("comparison body panic")
					}
					if err := process.filesCurrentForObservation(observed, files); err != nil {
						return err
					}
					if mode == "mutation" {
						return os.WriteFile(process.executable.path, []byte("changed original bytes"), 0700)
					}
					if mode == "cancel" {
						cancel()
					}
					if mode == "body-error" || mode == "swallowed" {
						return bodyFailure
					}
					return process.filesCurrentForObservation(observed, files)
				})
			})
			if (err == nil) != (mode == "clean") || calls > 1 {
				t.Fatal("comparison admission changed", mode, calls, err)
			}
			if (mode == "body-error" || mode == "swallowed") && !errors.Is(err, bodyFailure) {
				t.Fatal("original body error lost", err)
			}
			if mode == "closing-error" && !errors.Is(err, closingFailure) {
				t.Fatal("original tool closing error lost", err)
			}
			if retained != nil && process.filesCurrentForObservation(retainedCtx, retained) == nil {
				t.Fatal("file observation escaped callback")
			}
			if retainedCtx != nil && retainedCtx.Err() == nil {
				t.Fatal("callback context not revoked")
			}
			if late != nil && (late(ctx) == nil || calls != 0) {
				t.Fatal("late callback entered comparison")
			}
		})
	}
}

func TestDomainBaselineToolComparisonJoinsEarlyObserver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
	entered, joined := make(chan struct{}), make(chan struct{})
	returned := make(chan error, 1)
	err := domainTCPBaselineToolComparison(ctx, func(parent context.Context, use func(context.Context) error) error {
		go func() { returned <- use(parent) }()
		<-entered
		return nil
	}, func(observed context.Context) error {
		close(entered)
		<-observed.Done()
		close(joined)
		return observed.Err()
	})
	if err == nil {
		t.Fatal("early observer return accepted")
	}
	select {
	case <-joined:
	default:
		t.Fatal("comparison survived helper return")
	}
	if <-returned == nil {
		t.Fatal("canceled callback succeeded")
	}
}

func TestDomainBaselineToolComparisonNestedOriginalContext(t *testing.T) {
	process, ctx := domainFileObservationModel(t)
	ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
	observer := func(parent context.Context, use func(context.Context) error) error { return use(parent) }
	err := domainTCPBaselineToolComparison(ctx, observer, func(outer context.Context) error {
		return domainTCPBaselineToolComparison(outer, observer, func(inner context.Context) error {
			return process.withFileObservation(inner, func(files *xrayDomainTCPFileObservation) error {
				return process.filesCurrentForObservation(inner, files)
			})
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainBaselineToolComparisonJoinsBeforeObserverPanicEscapes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
	entered, joined := make(chan struct{}), make(chan struct{})
	returned := make(chan error, 1)
	witness := "original observer panic"
	func() {
		defer func() {
			if recover() != witness {
				t.Error("original observer panic was swallowed")
			}
			select {
			case <-joined:
			default:
				t.Error("panic escaped before comparison joined")
			}
		}()
		_ = domainTCPBaselineToolComparison(ctx, func(parent context.Context, use func(context.Context) error) error {
			go func() { returned <- use(parent) }()
			<-entered
			panic(witness)
		}, func(observed context.Context) error {
			close(entered)
			<-observed.Done()
			close(joined)
			return observed.Err()
		})
	}()
	if <-returned == nil {
		t.Fatal("canceled callback succeeded")
	}
}

func TestDomainBaselineToolComparisonCannotMintOriginalCurrent(t *testing.T) {
	f, kernel, runner := baselineCurrentComparison(t)
	for _, key := range []any{nil, domainTCPPreAddKey{}, domainTCPGuardReadKey{}, domainTCPBaselineCleanupKey{}, domainTCPCaptureCleanupKey{}, domainTCPFailureCleanupKey{}} {
		ctx := f.ctx
		if key != nil {
			ctx = context.WithValue(ctx, key, "foreign")
		}
		for _, read := range []func(context.Context) error{kernel.baseline.currentInOriginalFileObservation, kernel.baseline.currentBaselineInOriginalFileObservation} {
			if err := read(ctx); err == nil || runner.calls != 0 {
				t.Fatal("incomplete original admitted an observer", err, runner.calls)
			}
		}
	}
	kernel.baseline.backend.reader.Runner = &baselineCurrentUnobservedRunner{}
	if kernel.baseline.currentInOriginalFileObservation(f.ctx) == nil || runner.calls != 0 {
		t.Fatal("custom source acquired authority")
	}
}
