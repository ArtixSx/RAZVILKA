package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type nodeReadinessProcesses struct {
	proxyFakeProcesses
	afterStart func()
}

func (p *nodeReadinessProcesses) Start(ctx context.Context, spec ProcessSpec) error {
	err := p.proxyFakeProcesses.Start(ctx, spec)
	if p.afterStart != nil {
		p.afterStart()
	}
	return err
}

// Exercise the actual SOCKS exchange, not a delayed mock of readiness. A
// listener becoming usable after the budget must not admit a late success.
func TestExactNodeReadinessRejectsLateSOCKSGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	var started time.Time
	processStarted := make(chan struct{})
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(conn, greeting); err != nil {
					return
				}
				<-processStarted
				timer := time.NewTimer(time.Until(started.Add(8100 * time.Millisecond)))
				defer timer.Stop()
				select {
				case <-timer.C:
					_, _ = conn.Write([]byte{5, 0})
				case <-stop:
				}
			}()
		}
	}()
	defer func() {
		_ = listener.Close()
		close(stop)
		workers.Wait()
	}()
	checker := NewExactNodeChecker(t.TempDir())
	checker.Processes = &nodeReadinessProcesses{afterStart: func() { started = time.Now(); close(processStarted) }}
	err = checker.startSession(context.Background(), exactNodeSession{Address: listener.Addr().String()})
	elapsed := time.Since(started)
	t.Logf("loopback late greeting: elapsed_ms=%d accepted=%t", elapsed.Milliseconds(), err == nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("readiness accepted or misclassified a greeting after the eight-second budget: %v", err)
	}
	if elapsed > 8500*time.Millisecond {
		t.Fatalf("readiness exceeded its budget: %v", elapsed)
	}
}

func TestExactNodeRuntimeTimingsSeparateStartupFromIdentity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(conn, make([]byte, 3)); err == nil {
			_, _ = conn.Write([]byte{5, 0})
		}
	}()
	checker := fakeExactNodeChecker(t)
	now := time.Now()
	checker.now = func() time.Time { return now }
	checker.Processes = &nodeReadinessProcesses{afterStart: func() { now = now.Add(3 * time.Second) }}
	checker.start = func(ctx context.Context, session exactNodeSession) error {
		session.Address = listener.Addr().String()
		return checker.startSession(ctx, session)
	}
	identity := checker.identity
	checker.identity = func(session exactNodeSession) (routeidentity.Passport, error) {
		now = now.Add(7 * time.Millisecond)
		return identity(session)
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	_ = listener.Close()
	<-done
	if err != nil || !result.Available || result.CleanupStatus != NodeCleanupVerified {
		t.Fatalf("timing changed service admission: %+v %v", result, err)
	}
	want := map[string]int64{"runtime_start": 3000, "runtime_ready": 0, "route_identity": 7}
	for _, stage := range result.Stages {
		if duration, ok := want[stage.ID]; ok {
			if stage.Status != "passed" || stage.Duration != duration {
				t.Fatalf("startup and identity timings overlap: %+v", stage)
			}
			delete(want, stage.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing stages: %v", want)
	}
}

func TestExactNodeCanceledStartCannotBeginReadiness(t *testing.T) {
	checker := NewExactNodeChecker(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.Processes = &nodeReadinessProcesses{afterStart: cancel}
	var stages []NodeCheckStage
	ctx = context.WithValue(ctx, nodeRuntimeStagesKey{}, &stages)
	err := checker.startSession(ctx, exactNodeSession{Address: "127.0.0.1:1"})
	if !errors.Is(err, context.Canceled) || len(stages) != 1 || stages[0].ID != "runtime_start" || stages[0].Status != "failed" {
		t.Fatalf("canceled process start admitted readiness: %v %+v", err, stages)
	}
}
