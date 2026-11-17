//go:build linux && razvilka_native_fixture

package startuptools

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type domainGateSelectContext struct {
	context.Context
	once     sync.Once
	selected chan struct{}
}

func (c *domainGateSelectContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.selected) })
	return c.Context.Done()
}

func TestDomainNativeGateTimingActualWaitAndRelease(t *testing.T) {
	l := unitLease(t)
	stop := StartDomainNativeToolMeasurement()
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := l.lock(ctx); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			l.unlock()
		}
	}()
	released := false
	l.readRelease = func() {
		domainNativeGateMetrics.Lock()
		_, exists := domainNativeGateMetrics.held[l]
		domainNativeGateMetrics.Unlock()
		if !exists {
			t.Error("held timing ended before original release")
		}
		released = true
	}
	base, cancelWait := context.WithCancel(ctx)
	defer cancelWait()
	waitCtx := &domainGateSelectContext{Context: base, selected: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- l.lock(waitCtx) }()
	select {
	case <-waitCtx.selected:
	case <-ctx.Done():
		t.Fatal("wait did not reach select")
	}
	cancelWait()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("occupied canceled gate acquired")
		}
	case <-ctx.Done():
		t.Fatal("wait did not join")
	}
	l.unlock()
	locked = false
	if !released {
		t.Fatal("original read release skipped")
	}
	stop()
	snapshot := DomainNativeToolTimingSnapshot()
	if snapshot["wait/other/acquired"].Calls != 1 || snapshot["wait/other/context"].Calls != 1 || snapshot["held/other"].Calls != 1 {
		t.Fatalf("wrong intervals: %+v", snapshot)
	}
	if snapshot["wait/other/context"].Elapsed <= 0 || snapshot["held/other"].Elapsed <= 0 {
		t.Fatal("missing actual durations")
	}
	snapshot["held/other"] = DomainNativeToolTiming{}
	if DomainNativeToolTimingSnapshot()["held/other"].Calls != 1 {
		t.Fatal("snapshot alias")
	}
}

func TestDomainNativeGateTimingEpochAndBound(t *testing.T) {
	stop := StartDomainNativeToolMeasurement()
	old := domainNativeGateWait(&Lease{})
	oldHeld := &Lease{}
	domainNativeGateWait(oldHeld)("acquired")
	stop()
	stopNext := StartDomainNativeToolMeasurement()
	defer stopNext()
	old("acquired")
	domainNativeGateReleased(oldHeld)
	if DomainNativeToolTimingSnapshot()["wait/other/acquired"].Calls != 0 {
		t.Fatal("old epoch attributed to successor")
	}
	var leases [9]*Lease
	for i := range leases {
		leases[i] = &Lease{}
		domainNativeGateWait(leases[i])("acquired")
	}
	domainNativeGateMetrics.Lock()
	count := len(domainNativeGateMetrics.held)
	domainNativeGateMetrics.Unlock()
	if count != 8 {
		t.Fatalf("held pointer cap: %d", count)
	}
	for _, l := range leases {
		domainNativeGateReleased(l)
	}
	snapshot := DomainNativeToolTimingSnapshot()
	if snapshot["diagnostic/held-overflow-or-duplicate"].Calls != 1 || snapshot["held/other"].Calls != 8 {
		t.Fatalf("bound bookkeeping: %+v", snapshot)
	}
	for key := range snapshot {
		if strings.Contains(key, "TestDomain") || strings.Contains(key, "C:") || strings.Contains(key, "0x") {
			t.Fatalf("unbounded label %q", key)
		}
	}
	stopNext()
	domainNativeGateMetrics.Lock()
	defer domainNativeGateMetrics.Unlock()
	if len(domainNativeGateMetrics.held) != 0 {
		t.Fatal("retained leases after stop")
	}
}
