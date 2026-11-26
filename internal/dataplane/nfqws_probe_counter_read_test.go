package dataplane

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

type counterSuffixFormatModel struct {
	protocol string
	err      error
	formats  int
}

func (*counterSuffixFormatModel) Run(context.Context, string, ...string) ([]byte, error) {
	panic("suffix issued command")
}
func (m *counterSuffixFormatModel) NFQWSProbeCounterProtocol(context.Context, netidentity.Identity, string) (string, error) {
	m.formats++
	return m.protocol, m.err
}

type counterSuffixObserverModel struct {
	counterSuffixFormatModel
	observe      func(context.Context, func(context.Context) error) error
	observations int
}

func (m *counterSuffixObserverModel) WithReadOnlyToolObservation(c context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
	m.observations++
	if m.observe != nil {
		return m.observe(c, use)
	}
	return use(c)
}

func counterSuffixModel(t *testing.T, runner NFQWS2Runner) (*nfqwsProbeExecution, context.Context) {
	t.Helper()
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	c := &ManagedNFQWSProbeConsumer{panel: parent, gate: &NetworkPolicyAdapter{}}
	c.self = c
	c.inventory.reader.Runner = runner
	c.inventory.reader.CheckTools = func(context.Context, backendInventoryScope) error { return nil }
	c.inventory.review = strings.Repeat("a", 64)
	e := &nfqwsProbeExecution{consumer: c, socket: &nfqwsProbeSocketOwner{}, source: &strategylab.CandidateProbeReview{}, runtime: &components.ManagedNFQWSRuntimeLease{}, epoch: &strategylab.ManagedProbeEpoch{}, resource: &NFQWSExecutionResource{plan: &NFQWSScopedPlan{}}, binding: &NFQWSScopedBinding{}}
	e.self = e
	e.open.Store(true)
	c.active = e
	return e, context.WithValue(parent, nfqwsProbeExecutionKey{}, e)
}

func TestNFQWSProbeCounterSuffixOriginalErrorsAndFallback(t *testing.T) {
	sentinel := errors.New("original format refusal")
	old := &counterSuffixFormatModel{err: sentinel}
	e, ctx := counterSuffixModel(t, old)
	// Interface-absent path must not acquire any new association preconditions.
	e.source = nil
	var measurement nfqwsBoundaryMeasurement
	n, err := e.counterSuffix(ctx, nil, "x", &measurement)
	if n != 0 || !errors.Is(err, sentinel) || old.formats != 1 {
		t.Fatal(n, err, old.formats)
	}
	for _, tc := range []struct {
		name, protocol, raw string
		formatErr           error
		want                error
		observations        int
	}{
		{"format", "", "", sentinel, sentinel, 1},
		{"parse", "tcp", "bad", nil, ErrNFQWSScopedOwner, 1},
		{"closing", "tcp", "Chain RZP_012345678901234567_4 (1 references)\n pkts bytes target prot opt in out source destination\n 12 1024 NFQUEUE tcp -- * * 192.168.1.1 8.8.8.8 tcp spt:35001 dpt:443 mark match 0x0 NFQUEUE num 200\n", nil, ErrNFQWSScopedOwner, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := &counterSuffixObserverModel{counterSuffixFormatModel: counterSuffixFormatModel{protocol: tc.protocol, err: tc.formatErr}}
			e, ctx := counterSuffixModel(t, model)
			n, err := e.counterSuffix(ctx, []byte(tc.raw), "RZP_012345678901234567_4", &measurement)
			if n != 0 || !errors.Is(err, tc.want) || model.formats != 1 || model.observations != tc.observations {
				t.Fatalf("original suffix error/order changed n=%d err=%v format=%d observations=%d", n, err, model.formats, model.observations)
			}
		})
	}
	model := &counterSuffixObserverModel{observe: func(context.Context, func(context.Context) error) error { return sentinel }}
	e, ctx = counterSuffixModel(t, model)
	if n, err := e.counterSuffix(ctx, nil, "x", &measurement); n != 0 || !errors.Is(err, sentinel) || model.formats != 0 {
		t.Fatal("observer failure fell back", n, err, model.formats)
	}
}

func TestNFQWSProbeCounterSuffixFrozenAssociations(t *testing.T) {
	changes := map[string]func(*nfqwsProbeExecution){
		"execution-self": func(e *nfqwsProbeExecution) { e.self = &nfqwsProbeExecution{} },
		"consumer":       func(e *nfqwsProbeExecution) { e.consumer = &ManagedNFQWSProbeConsumer{} },
		"socket":         func(e *nfqwsProbeExecution) { e.socket = &nfqwsProbeSocketOwner{} },
		"source":         func(e *nfqwsProbeExecution) { e.source = &strategylab.CandidateProbeReview{} },
		"runtime":        func(e *nfqwsProbeExecution) { e.runtime = &components.ManagedNFQWSRuntimeLease{} },
		"epoch":          func(e *nfqwsProbeExecution) { e.epoch = &strategylab.ManagedProbeEpoch{} },
		"resource":       func(e *nfqwsProbeExecution) { e.resource = &NFQWSExecutionResource{} },
		"plan":           func(e *nfqwsProbeExecution) { e.resource.plan = &NFQWSScopedPlan{} },
		"binding":        func(e *nfqwsProbeExecution) { e.binding = &NFQWSScopedBinding{} },
		"collector":      func(e *nfqwsProbeExecution) { e.consumer.inventory.reader.Runner = &counterSuffixObserverModel{} },
		"review":         func(e *nfqwsProbeExecution) { e.consumer.inventory.review = "changed" },
		"provider":       func(e *nfqwsProbeExecution) { e.consumer.inventory.reader.Provider = netidentity.NewProcProvider() },
		"tools":          func(e *nfqwsProbeExecution) { e.binding.Tools.IPTables = "changed" },
		"runtime-runner": func(e *nfqwsProbeExecution) { e.consumer.runtimeRunner = &counterSuffixObserverModel{} },
		"closed":         func(e *nfqwsProbeExecution) { e.open.Store(false) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			e, ctx := counterSuffixModel(t, &counterSuffixObserverModel{})
			current, err := e.counterSuffixCurrent(ctx)
			if err != nil {
				t.Fatal(err)
			}
			change(e)
			if current(ctx) == nil {
				t.Fatal("association drift admitted")
			}
		})
	}
}

func TestNFQWSProbeCounterSuffixOnceClosingAndMisuse(t *testing.T) {
	e, ctx := counterSuffixModel(t, &counterSuffixObserverModel{})
	current, err := e.counterSuffixCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("original body or closing")
	for _, mode := range []string{"success", "no-callback", "double", "swallowed", "closing", "recovered-panic", "foreign-context", "late"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var late func(context.Context) error
			observe := func(c context.Context, use func(context.Context) error) error {
				switch mode {
				case "no-callback":
					return nil
				case "foreign-context":
					return use(context.Background())
				case "late":
					late = use
					return nil
				case "recovered-panic":
					func() { defer func() { _ = recover() }(); _ = use(c) }()
					return nil
				}
				err := use(c)
				if mode == "double" {
					_ = use(c)
				}
				if mode == "swallowed" {
					return nil
				}
				if mode == "closing" {
					return sentinel
				}
				return err
			}
			n, err := nfqwsProbeCounterSuffixOnce(ctx, observe, current, func(context.Context) (uint64, error) {
				calls++
				if mode == "recovered-panic" {
					panic("body")
				}
				if mode == "swallowed" {
					return 23, sentinel
				}
				return 23, nil
			})
			if mode == "success" {
				if n != 23 || err != nil || calls != 1 {
					t.Fatal(n, err, calls)
				}
				return
			}
			if n != 0 || err == nil || calls > 1 {
				t.Fatal("invalid count escaped", n, err, calls)
			}
			if (mode == "swallowed" || mode == "closing") && !errors.Is(err, sentinel) {
				t.Fatal("original cause lost", err)
			}
			if late != nil {
				if late(ctx) == nil || calls != 0 {
					t.Fatal("late callback ran")
				}
			}
		})
	}
}

func TestNFQWSProbeCounterSuffixJoinsObserverAbort(t *testing.T) {
	for _, mode := range []string{"return", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			e, ctx := counterSuffixModel(t, &counterSuffixObserverModel{})
			current, err := e.counterSuffixCurrent(ctx)
			if err != nil {
				t.Fatal(err)
			}
			entered, exited, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_, _ = nfqwsProbeCounterSuffixOnce(ctx, func(c context.Context, use func(context.Context) error) error {
					go func() { _ = use(c) }()
					<-entered
					if mode == "panic" {
						panic("observer")
					}
					if mode == "goexit" {
						runtime.Goexit()
					}
					return nil
				}, current, func(c context.Context) (uint64, error) { close(entered); <-c.Done(); close(exited); return 99, c.Err() })
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("observer failed to join")
			}
			select {
			case <-exited:
			default:
				t.Fatal("body escaped observer")
			}
		})
	}
}

func TestNFQWSProbeCounterSuffixParentCancelAndContext(t *testing.T) {
	e, ctx := counterSuffixModel(t, &counterSuffixObserverModel{})
	parent, cancel := context.WithCancel(ctx)
	current, err := e.counterSuffixCurrent(parent)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	n, err := nfqwsProbeCounterSuffixOnce(parent, func(_ context.Context, use func(context.Context) error) error {
		// Same original marker/deadline, but deliberately detached Done. The local
		// helper must link parent cancellation independently of observer behavior.
		deadline, _ := ctx.Deadline()
		detached, stop := context.WithDeadline(context.WithoutCancel(ctx), deadline)
		defer stop()
		return use(detached)
	}, current, func(c context.Context) (uint64, error) { once.Do(cancel); <-c.Done(); return 44, c.Err() })
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("parent cancellation lost", n, err)
	}
	foreign := context.WithValue(ctx, nfqwsProbeExecutionKey{}, &nfqwsProbeExecution{})
	if nfqwsProbeCounterSuffixContext(ctx, foreign, e) == nil {
		t.Fatal("foreign execution accepted")
	}
	cleanup := context.WithValue(ctx, nfqwsProbeCleanupKey{}, e)
	if nfqwsProbeCounterSuffixContext(ctx, cleanup, e) == nil {
		t.Fatal("cleanup borrowed")
	}
}

type probeSuffixDeadlineModel struct {
	context.Context
	deadline time.Time
	finite   bool
}

func (c probeSuffixDeadlineModel) Deadline() (time.Time, bool) { return c.deadline, c.finite }
func (probeSuffixDeadlineModel) Err() error                    { return nil }

func TestNFQWSProbeCounterSuffixDeadlineAndClosingAssociation(t *testing.T) {
	e, ctx := counterSuffixModel(t, &counterSuffixObserverModel{})
	deadline, _ := ctx.Deadline()
	for _, child := range []context.Context{
		probeSuffixDeadlineModel{ctx, deadline.Add(time.Second), true},
		probeSuffixDeadlineModel{ctx, time.Now().Add(-time.Second), true},
		probeSuffixDeadlineModel{ctx, time.Time{}, false},
	} {
		if nfqwsProbeCounterSuffixContext(ctx, child, e) == nil {
			t.Fatal("invalid deadline accepted")
		}
	}
	current, err := e.counterSuffixCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, err := nfqwsProbeCounterSuffixOnce(ctx, func(c context.Context, use func(context.Context) error) error {
		err := use(c)
		e.binding.Tools.IPTables = "late-rebound"
		return err
	}, current, func(context.Context) (uint64, error) { return 77, nil })
	if n != 0 || err == nil {
		t.Fatal("positive scalar escaped late association", n, err)
	}
}

type probeSuffixContextInitialization struct {
	context.Context
	done func() <-chan struct{}
}

func (c probeSuffixContextInitialization) Done() <-chan struct{} { return c.done() }

func TestNFQWSProbeCounterSuffixContextInitializationJoins(t *testing.T) {
	for _, mode := range []string{"reenter", "panic", "goexit", "early-return"} {
		t.Run(mode, func(t *testing.T) {
			e, baseCtx := counterSuffixModel(t, &counterSuffixObserverModel{})
			ctx, cancelParent := context.WithCancel(baseCtx)
			defer cancelParent()
			current, err := e.counterSuffixCurrent(ctx)
			if err != nil {
				t.Fatal(err)
			}
			done, initializing, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			calls := 0
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				n, err := nfqwsProbeCounterSuffixOnce(ctx, func(c context.Context, use func(context.Context) error) error {
					var once sync.Once
					owner := probeSuffixContextInitialization{Context: c, done: func() <-chan struct{} {
						once.Do(func() {
							switch mode {
							case "reenter":
								_ = use(c)
							case "panic":
								panic("context")
							case "goexit":
								runtime.Goexit()
							case "early-return":
								close(initializing)
								<-release
							}
						})
						return nil
					}}
					if mode == "early-return" {
						go func() { _ = use(owner) }()
						<-initializing
						cancelParent()
						close(release)
						return nil
					}
					return use(owner)
				}, current, func(context.Context) (uint64, error) { calls++; return 99, nil })
				if n != 0 || err == nil {
					t.Errorf("initialization misuse published %d %v", n, err)
				}
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("context initialization leaked or deadlocked")
			}
			if calls != 0 {
				t.Fatal("invalid context reached body", calls)
			}
		})
	}
}
