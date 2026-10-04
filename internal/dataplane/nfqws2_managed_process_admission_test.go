package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

type nfqws2ManagedStartModel struct {
	in       []nfqws2ManagedStartFrame
	out      []nfqws2ManagedStartFrame
	failure  error
	received func()
}

func (m *nfqws2ManagedStartModel) send(frame nfqws2ManagedStartFrame) error {
	m.out = append(m.out, frame)
	return m.failure
}
func (m *nfqws2ManagedStartModel) receive() (nfqws2ManagedStartFrame, error) {
	if m.received != nil {
		m.received()
	}
	if m.failure != nil || len(m.in) == 0 {
		return nfqws2ManagedStartFrame{}, ErrNFQWSManagedProcessUnknown
	}
	frame := m.in[0]
	m.in = m.in[1:]
	return frame, nil
}
func (m *nfqws2ManagedStartModel) close() error { return nil }

func nfqws2ManagedStartFixture(t *testing.T) (nfqws2ManagedProcessCommand, nfqws2ManagedStartBinding, nfqws2ManagedStartFrame, nfqws2ManagedStartFrame) {
	t.Helper()
	_, lease := nfqws2ManagedRecordFixture(t)
	terminal := nfqws2ManagedModelTerminal(lease)
	binding := nfqws2ManagedStartBinding{ExecutionID: "dp-check-" + strings.Repeat("1", 32), PlanID: "dp-0123456789abcdef", PlanDigest: strings.Repeat("2", 64), ResourceID: "nq-" + strings.Repeat("3", 32), ResourceGeneration: strings.Repeat("4", 64), EffectsDigest: strings.Repeat("5", 64), SessionID: lease.Command.ID, CommandSHA256: lease.CommandSHA256}
	helper := components.NFQWSSupervisionIdentity{BootID: terminal.Receipt.BootID, Start: terminal.Receipt.Start, PID: terminal.Receipt.PID, Group: terminal.Receipt.Group}
	ready, err := nfqws2ManagedStartBase(lease.Command, binding, helper)
	if err != nil {
		t.Fatal(err)
	}
	ready.Kind = "ready"
	started := ready
	started.Kind, started.Child = "started", terminal.Child
	return lease.Command, binding, ready, started
}

func TestNFQWSManagedStartBindingIsOutsideCommandDigest(t *testing.T) {
	_, lease := nfqws2ManagedRecordFixture(t)
	_, binding, _, _ := nfqws2ManagedStartFixture(t)
	command := lease.Command
	binding.CommandSHA256 = lease.CommandSHA256
	before := nfqws2ManagedCommandDigest(command)
	lease.LaunchBinding = &binding
	image, err := nfqws2ManagedLeaseImage(lease)
	if err != nil {
		t.Fatal(err)
	}
	got, err := nfqws2DecodeManagedLease(image, lease.StateRoot, lease.Owner)
	if err != nil || got.LaunchBinding == nil || *got.LaunchBinding != binding || got.CommandSHA256 != before {
		t.Fatal("exact independent binding lost", err)
	}
	for _, mutate := range []func(*nfqws2ManagedStartBinding){
		func(b *nfqws2ManagedStartBinding) { b.SessionID = strings.Repeat("f", 32) },
		func(b *nfqws2ManagedStartBinding) { b.CommandSHA256 = strings.Repeat("f", 64) },
		func(b *nfqws2ManagedStartBinding) { b.ResourceID = "../other" },
		func(b *nfqws2ManagedStartBinding) { b.ExecutionID = "dp-check-" },
	} {
		bad := binding
		mutate(&bad)
		lease.LaunchBinding = &bad
		if _, err := nfqws2ManagedLeaseImage(lease); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
			t.Fatal("unbound launch metadata accepted", err)
		}
	}
	if nfqws2ManagedCommandDigest(command) != before {
		t.Fatal("binding created circular command hash")
	}
}

func TestNFQWSManagedStartProtocolRejectsForeignAndLostACK(t *testing.T) {
	command, binding, ready, started := nfqws2ManagedStartFixture(t)
	for _, mode := range []string{"exact", "foreign-resource", "foreign-helper", "ready-with-child", "lost-ack", "foreign-command", "foreign-child", "cancel-before-permit", "revoked-before-permit", "replayed-ready"} {
		t.Run(mode, func(t *testing.T) {
			first, last := ready, started
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			current := func() error { return nil }
			switch mode {
			case "foreign-resource":
				first.Binding.ResourceID = "nq-" + strings.Repeat("f", 32)
			case "foreign-helper":
				first.Helper.Start = "999"
			case "ready-with-child":
				first.Child = last.Child
			case "foreign-command":
				last.Binding.CommandSHA256 = strings.Repeat("f", 64)
			case "foreign-child":
				last.Child.ArgumentsSHA256 = strings.Repeat("f", 64)
			case "cancel-before-permit":
				cancel()
			case "revoked-before-permit":
				current = func() error { return ErrNFQWSScopedOwner }
			case "replayed-ready":
				last = first
			}
			transport := &nfqws2ManagedStartModel{in: []nfqws2ManagedStartFrame{first, last}}
			if mode == "lost-ack" {
				transport.in = transport.in[:1]
			}
			err := nfqws2ManagedStartParent(ctx, transport, command, binding, ready.Helper, current)
			if (err == nil) != (mode == "exact") {
				t.Fatal("unacknowledged/foreign start became successful", err)
			}
			if strings.Contains(mode, "before-permit") || mode == "foreign-resource" || mode == "foreign-helper" || mode == "ready-with-child" {
				if len(transport.out) != 0 {
					t.Fatal("permit sent without exact live ready")
				}
			} else if len(transport.out) != 1 || transport.out[0].Kind != "permit" {
				t.Fatal("permit replayed", transport.out)
			}
		})
	}
}

func TestNFQWSManagedHelperConsumesPermitOnce(t *testing.T) {
	command, _, ready, started := nfqws2ManagedStartFixture(t)
	for _, mode := range []string{"exact", "missing", "foreign", "cancel", "revoked", "start-error"} {
		t.Run(mode, func(t *testing.T) {
			permit := ready
			permit.Kind = "permit"
			base := ready
			base.Kind = ""
			transport := &nfqws2ManagedStartModel{in: []nfqws2ManagedStartFrame{permit}}
			if mode == "missing" {
				transport.in = nil
			}
			if mode == "foreign" {
				transport.in[0].Binding.EffectsDigest = strings.Repeat("f", 64)
			}
			h := &nfqws2ManagedStartHelper{transport: transport, base: base}
			if h.ready() != nil || h.ready() == nil {
				t.Fatal("ready replay")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			current := func() error {
				if mode == "revoked" {
					return ErrNFQWSScopedOwner
				}
				return nil
			}
			calls := 0
			begin := func() error {
				calls++
				if mode == "start-error" {
					return ErrNFQWSManagedProcessUnknown
				}
				return nil
			}
			err := h.admit(ctx, current, begin)
			if (err == nil) != (mode == "exact") || calls != map[bool]int{true: 1, false: 0}[mode == "exact" || mode == "start-error"] {
				t.Fatal("invalid permit called Start", calls, err)
			}
			if h.admit(context.Background(), current, begin) == nil || calls > 1 {
				t.Fatal("consumed permit replayed")
			}
			if mode == "exact" && (h.started(command, started.Child) != nil || h.started(command, started.Child) == nil) {
				t.Fatal("ACK replay")
			}
		})
	}
}

func TestNFQWSManagedStartFrameStrictBoundedDecoder(t *testing.T) {
	_, _, ready, _ := nfqws2ManagedStartFixture(t)
	data, _ := json.Marshal(ready)
	if _, err := nfqws2ManagedStartDecode(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte(strings.Repeat(" ", nfqws2ManagedStartFrameLimit+1)), append(append([]byte{}, data...), []byte(" {}")...), []byte(`{"version":1,"Version":1,"kind":"ready"}`), []byte(`{"version":1,"kind":"ready","extra":0}`), []byte(`{"version":2,"kind":"ready"}`), []byte(`{"version":1,"kind":"grant"}`)} {
		if _, err := nfqws2ManagedStartDecode(bad); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
			t.Fatal("ambiguous frame accepted", err)
		}
	}
}

func TestNFQWSScopedCurrentProofNeverGrantsCaptureWriter(t *testing.T) {
	b, model, root := nfqwsScopedBindingFixture(t)
	b.ApplyGuard = func(context.Context, *NFQWSScopedPlan, PolicyEffect) error { return ErrReviewChanged }
	checks := 0
	current := func(_ context.Context, got *NFQWSScopedPlan) error {
		checks++
		if got != model.p {
			return ErrReviewChanged
		}
		return nil
	}
	model.running = false
	if err := nfqwsScopedBeforeStartCurrent(context.Background(), b, model.p, current); err != nil {
		t.Fatal("current prestart proof rejected", err)
	}
	model.running = true
	if err := nfqwsScopedPreparedCurrent(context.Background(), b, model.p, root, current); err != nil {
		t.Fatal("current prepared proof rejected", err)
	}
	if checks == 0 || len(model.calls) != 0 {
		t.Fatal("proof performed a kernel effect")
	}
	if err := b.Apply(context.Background(), model.p, root); !errors.Is(err, ErrReviewChanged) || len(model.calls) != 0 {
		t.Fatal("read-only Current became writer grant", err)
	}
	if err := nfqwsScopedPreparedCurrent(context.Background(), b, model.p, root, func(context.Context, *NFQWSScopedPlan) error { return ErrReviewChanged }); !errors.Is(err, ErrReviewChanged) {
		t.Fatal("revoked current guard accepted", err)
	}
}

func TestNFQWSManagedDelayedREADYCancelNeverSendsPermit(t *testing.T) {
	command, binding, ready, started := nfqws2ManagedStartFixture(t)
	for _, stage := range []string{"while-ready-blocked", "inside-late-current", "inside-ack-current"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := &nfqws2ManagedStartModel{in: []nfqws2ManagedStartFrame{ready, started}}
			if stage == "while-ready-blocked" {
				entered, release := make(chan struct{}), make(chan struct{})
				transport.received = func() { close(entered); <-release }
				go func() { <-entered; cancel(); close(release) }()
			}
			checks := 0
			current := func() error {
				checks++
				if stage == "inside-late-current" || (stage == "inside-ack-current" && checks == 2) {
					cancel()
				}
				return nil // A nominally successful reader cannot conceal cancel.
			}
			if err := nfqws2ManagedStartParent(ctx, transport, command, binding, ready.Helper, current); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
				t.Fatal("cancel became acknowledged launch", err)
			}
			want := 0
			if stage == "inside-ack-current" {
				want = 1
			}
			if len(transport.out) != want {
				t.Fatal("cancel before permit admitted Start", len(transport.out))
			}
		})
	}
}

func TestNFQWSManagedStartDeadlinePreservesOriginalCancellation(t *testing.T) {
	type contextMarker struct{}
	original, stop := context.WithCancel(context.WithValue(context.Background(), contextMarker{}, "original"))
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	bounded, cancel, err := nfqws2ManagedStartContext(original, deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	got, present := bounded.Deadline()
	if !present || !got.Equal(deadline) || bounded.Value(contextMarker{}) != "original" {
		t.Fatal("bounded context detached original scope")
	}
	stop()
	if bounded.Err() != context.Canceled {
		t.Fatal("bounded scope ignored original cancel")
	}
	short := time.Now().Add(time.Second)
	earlier, release := context.WithDeadline(context.Background(), short)
	defer release()
	boundedEarlier, cancelEarlier, err := nfqws2ManagedStartContext(earlier, deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEarlier()
	if got, _ := boundedEarlier.Deadline(); !got.Equal(short) {
		t.Fatal("command extended original deadline")
	}
	for _, invalid := range []time.Time{time.Time{}, time.Now().Add(-time.Second), time.Now().Add(16 * time.Second)} {
		if _, _, err := nfqws2ManagedStartContext(context.Background(), invalid); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
			t.Fatal("unbounded launch context accepted", err)
		}
	}
}

func TestNFQWSManagedStartExceptionalExitRevokesRetainedBegin(t *testing.T) {
	for _, mode := range []string{"panic-before-begin", "panic-after-begin", "swallowed-begin-panic", "ignored-begin-error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			gate := &nfqws2ManagedStartOnce{open: true, begin: func() error {
				calls++
				if mode == "swallowed-begin-panic" {
					panic("begin fixture")
				}
				if mode == "ignored-begin-error" {
					return ErrNFQWSManagedProcessUnknown
				}
				return nil
			}}
			var retained func() error
			panicked := false
			var result error
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				result = gate.invoke(func(begin func() error) error {
					retained = begin
					if mode == "panic-before-begin" {
						panic("scope fixture")
					}
					if mode == "swallowed-begin-panic" {
						func() { defer func() { _ = recover() }(); _ = begin() }()
						return nil
					}
					_ = begin()
					if mode == "panic-after-begin" {
						panic("scope fixture")
					}
					return nil
				})
			}()
			if (mode == "panic-before-begin" || mode == "panic-after-begin") != panicked {
				t.Fatal("panic incorrectly swallowed")
			}
			if !panicked && !errors.Is(result, ErrNFQWSManagedProcessUnknown) {
				t.Fatal("exceptional begin became success", result)
			}
			before := calls
			if retained == nil || !errors.Is(retained(), ErrNFQWSManagedProcessUnknown) || calls != before {
				t.Fatal("late borrowed Start survived exceptional completion")
			}
		})
	}
}

func TestNFQWSManagedStartAdmissionRequiresLateCurrent(t *testing.T) {
	command, binding, _, _ := nfqws2ManagedStartFixture(t)
	guard := func(context.Context, nfqws2ManagedStartBinding) error { return nil }
	admission := nfqws2ManagedProcessAdmission{Binding: binding, BeforeStart: guard, Current: guard, Prepared: guard, WithStart: func(_ context.Context, _ nfqws2ManagedStartBinding, begin func() error) error { return begin() }}
	if !admission.valid(command) {
		t.Fatal("exact live callback contract refused")
	}
	admission.Current = nil
	if admission.valid(command) {
		t.Fatal("opening WithStart replaced required late Current")
	}
}
