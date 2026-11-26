package dataplane

import (
	"context"
	"errors"
	"testing"
)

type recoveryStopObserverFixture struct {
	*fakeAdapter
	err   error
	after func()
}

func (a *recoveryStopObserverFixture) VerifyRuntimeInactive(ctx context.Context) error {
	if a.after != nil {
		a.after()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return a.err
}
func TestNFQWS2RecoveryStopObservationClosesRegistryAndPlan(t *testing.T) {
	for _, kind := range []string{"valid", "current-process", "foreign-queue", "registry", "mixed", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			m := New(t.TempDir())
			a := &recoveryStopObserverFixture{fakeAdapter: &fakeAdapter{id: "nfqws2"}}
			m.Register(a)
			p, e := Build(Input{Revision: 1, Routes: []Route{{ServiceID: "video", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"video.example"}}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Running: true}}, Host: HostState{IPTables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true}})
			if e != nil {
				t.Fatal(e)
			}
			p.Ready = true
			p.State = "committed"
			if e = m.Record(p); e != nil {
				t.Fatal(e)
			}
			p, _, _ = m.Committed()
			ctx := context.Background()
			switch kind {
			case "current-process", "foreign-queue":
				a.err = errors.New(kind)
			case "registry":
				a.after = func() { m.Register(&fakeAdapter{id: "other"}) }
			case "mixed":
				p.Adapters = append(p.Adapters, "sing-box")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			e = m.ObserveNFQWS2RecoveryStopInactive(ctx, p)
			if kind == "valid" && e != nil || kind != "valid" && e == nil {
				t.Fatal(kind, e)
			}
			if len(a.calls) > 0 {
				t.Fatal("observation mutated runtime")
			}
		})
	}
}
