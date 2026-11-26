package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestOfflineRollbackRuntimeRetainsOriginalSourceUntilRecoveryCompletes(t *testing.T) {
	for _, failed := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		manager := dataplane.New(t.TempDir())
		operationErr, closeErr := errors.New("recovery refused"), errors.New("source closure refused")
		active, closed := false, false
		bind := func(got context.Context, create func() (*dataplane.Manager, error), dns string) (*dataplane.Manager, func() error, error) {
			actual, err := create()
			if got != ctx || actual != manager || err != nil || dns != "owned-dns" {
				t.Fatal("recovery replaced the actual owner or its original context")
			}
			active = true
			return actual, func() error { active, closed = false, true; return closeErr }, nil
		}
		result, err := withOfflineRollbackRuntime(ctx, manager, "owned-dns", func() (dataplane.Execution, error) {
			if !active || closed || ctx.Err() != nil {
				t.Fatal("source expired before recovery completed")
			}
			if failed {
				return dataplane.Execution{}, operationErr
			}
			return dataplane.Execution{State: "rolled-back"}, nil
		}, bind)
		cancel()
		if active || !closed || !errors.Is(err, closeErr) || errors.Is(err, operationErr) != failed || !failed && result.State != "rolled-back" {
			t.Fatal("source closure or recovery outcome was lost", result, err)
		}
	}
}

func TestOfflineRollbackRuntimeRefusesMissingOrDifferentSourceBeforeRecovery(t *testing.T) {
	for _, mode := range []string{"source-error", "different-manager", "missing-close"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		manager := dataplane.New(t.TempDir())
		closed := false
		bind := func(context.Context, func() (*dataplane.Manager, error), string) (*dataplane.Manager, func() error, error) {
			closeSource := func() error { closed = true; return nil }
			switch mode {
			case "source-error":
				return nil, closeSource, errors.New("source refused")
			case "different-manager":
				return dataplane.New(t.TempDir()), closeSource, nil
			default:
				return manager, nil, nil
			}
		}
		_, err := withOfflineRollbackRuntime(ctx, manager, "owned-dns", func() (dataplane.Execution, error) {
			t.Fatal("recovery ran without its actual retained source")
			return dataplane.Execution{}, nil
		}, bind)
		cancel()
		if !errors.Is(err, dataplane.ErrRuntimeInactivity) || closed != (mode != "missing-close") {
			t.Fatal("source refusal or closure was lost", mode, err)
		}
	}
}

func TestOfflineRollbackRuntimeProductionBindingRejectsUnboundedContext(t *testing.T) {
	_, err := withOfflineRollbackRuntime(context.Background(), dataplane.New(t.TempDir()), "owned-dns", func() (dataplane.Execution, error) {
		t.Fatal("unbounded recovery acquired runtime authority")
		return dataplane.Execution{}, nil
	}, runtimeManagerSourcesBound)
	if !errors.Is(err, dataplane.ErrRuntimeInactivity) || selfUpdateRuntimeManagerFailureStage(err) != "manager-context" {
		t.Fatal("production binding did not refuse its original invalid context", err)
	}
}
