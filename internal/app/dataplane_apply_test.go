package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestApplicationFenceWaitsForRollbackAndProtectsNextCaller(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "unconfirmed"}[failed], func(t *testing.T) {
			a := &App{Dataplane: dataplane.New(t.TempDir())}
			entered, finish := make(chan struct{}), make(chan struct{})
			adapter := &nodeApplyAdapter{after: func(phase string) error {
				if phase == "health" {
					return errors.New("candidate failed")
				}
				if phase == "rollback" {
					close(entered)
					<-finish
					if failed {
						return errors.New("restore not confirmed")
					}
				}
				return nil
			}}
			if err := a.Dataplane.Register(adapter); err != nil {
				t.Fatal(err)
			}
			plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-fence", Digest: strings.Repeat("a", 64), Ready: true, Adapters: []string{"sing-box"}}
			release, err := a.Operations.Exclusive(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			type result struct {
				execution dataplane.Execution
				err       error
			}
			done := make(chan result, 1)
			go func() {
				execution, err := a.applyDataplane(context.Background(), plan, nil)
				done <- result{execution, err}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(finish)
				t.Fatal("rollback not entered")
			}
			before := a.Operations.Snapshot()
			if !before.Exclusive || before.Fenced {
				close(finish)
				<-done
				t.Fatal("rollback lease was released or cleanup was fenced early")
			}
			if _, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
				close(finish)
				<-done
				t.Fatal("another mutation entered during cleanup", err)
			}
			close(finish)
			out := <-done
			want := "rolled-back"
			if failed {
				want = "rollback-failed"
			}
			if out.err == nil || out.execution.State != want || a.Operations.Snapshot().Fenced != failed || !a.Operations.Snapshot().Exclusive {
				t.Fatal(out, a.Operations.Snapshot())
			}
			release()
			if failed {
				calls := append([]string{}, adapter.calls...)
				_, err := a.applyDataplane(context.Background(), plan, func() (func() error, error) { t.Fatal("fenced commit ran"); return nil, nil })
				if !errors.Is(err, operationgate.ErrRecovery) || !reflect.DeepEqual(calls, adapter.calls) {
					t.Fatal("fenced caller mutated runtime")
				}
				if _, err := a.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrRecovery) {
					t.Fatal("fence lost with original lease", err)
				}
			} else {
				next, err := a.Operations.Exclusive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				next()
			}
		})
	}
}
