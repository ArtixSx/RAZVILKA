package dnscontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Explicit phase model: the Gate and source are actual, while this test owner
// retains the admitted original context in place of Manager's private carrier.
type syntheticDNSPhaseModel struct {
	phase  context.Context
	mode   string
	refuse func(context.Context, func(context.Context) error) error
}

func (*syntheticDNSPhaseModel) WithSyntheticPublication(context.Context, *SyntheticDNSMapping, func(context.Context) error) error {
	return ErrSyntheticDNSMappingRequired
}
func (*syntheticDNSPhaseModel) CurrentSyntheticMapping(context.Context, *SyntheticDNSMapping) error {
	return ErrSyntheticDNSMappingRequired
}
func (*syntheticDNSPhaseModel) WithSyntheticWireSend(context.Context, *SyntheticDNSMapping, func() error) error {
	return ErrSyntheticDNSMappingRequired
}
func (o *syntheticDNSPhaseModel) WithSyntheticRequestPhase(request context.Context, use func(context.Context) error) error {
	if o.refuse != nil {
		return o.refuse(request, use)
	}
	if o.mode == "missing" {
		return nil
	}
	if o.mode == "unbounded" {
		return use(context.Background())
	}
	deadline, _ := request.Deadline()
	c, cancel := context.WithDeadline(o.phase, deadline)
	defer cancel()
	err := use(c)
	if o.mode == "twice" {
		return errors.Join(err, use(c))
	}
	return err
}

func TestSyntheticDNSPhaseEntersBeforeListenerAdmissionAndReserve(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	owner := &syntheticDNSPhaseModel{}
	s := f.source(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, release, err := f.gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	owner.phase = held
	request, cancelRequest := context.WithTimeout(context.Background(), time.Second)
	defer cancelRequest()
	if err := s.admitSyntheticRequest(request, f.client); err != nil {
		t.Fatal("listener admission failed before publication lease", err)
	}
	query := scopedQuery(t, "service.example.com", 1)
	mapping, err := s.Reserve(request, f.client, query)
	if err != nil || mapping == nil {
		t.Fatal("Reserve lost original operation before publication", err)
	}
	if err := mapping.Current(held); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticDNSPhaseRequestCancellationLeavesSameSourceUsable(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	owner := &syntheticDNSPhaseModel{}
	s := f.source(t, owner)
	life, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	held, release, err := f.gate.ExclusiveContext(life)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	owner.phase = held
	query := scopedQuery(t, "other.example.com", dnsmessage.TypeA)
	var answer []byte
	send := func(wire []byte) error { answer = wire; return nil }

	canceled, cancel := context.WithCancel(life)
	cancel()
	owner.refuse = func(context.Context, func(context.Context) error) error {
		t.Fatal("an already canceled request invoked the phase owner")
		return nil
	}
	if err := s.Publish(canceled, f.client, query, send); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	request, cancelRequest := context.WithCancel(life)
	defer cancelRequest()
	owner.refuse = func(request context.Context, _ func(context.Context) error) error {
		cancelRequest()
		return request.Err()
	}
	if err := s.Publish(request, f.client, query, send); !errors.Is(err, context.Canceled) || errors.Is(err, ErrSyntheticDNSMapping) {
		t.Fatalf("before-callback cancellation poisoned the source: %v", err)
	}
	if answer != nil || s.invalid.Load() || s.ctx.Err() != nil || len(s.ledger.Reservations) != 0 {
		t.Fatal("a canceled request published, reserved, or stopped the source")
	}

	owner.refuse = nil
	if err := s.admitSyntheticRequest(life, f.client); err != nil {
		t.Fatal("next listener admission on the same source failed", err)
	}
	if err := s.Publish(life, f.client, query, send); err != nil {
		t.Fatal("next reply on the same source failed", err)
	}
	var packet dnsmessage.Message
	if err := packet.Unpack(answer); err != nil || len(packet.Answers) != 1 {
		t.Fatalf("next request did not receive a DNS answer: %v", err)
	}
	address, ok := packet.Answers[0].Body.(*dnsmessage.AResource)
	if !ok || address.A != [4]byte{1, 1, 1, 1} {
		t.Fatalf("next request did not receive its reviewed baseline A record: %+v", packet.Answers)
	}
}

func TestSyntheticDNSPhaseCancellationDoesNotExcuseOwnerFault(t *testing.T) {
	for _, failure := range []string{"joined-fault", "false-cancellation", "late-callback"} {
		t.Run(failure, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, nil)
			owner := &syntheticDNSPhaseModel{}
			s := f.source(t, owner)
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			var late func(context.Context) error
			fault := errors.New("owner fault during cancellation")
			owner.refuse = func(request context.Context, use func(context.Context) error) error {
				if failure == "false-cancellation" {
					return context.Canceled
				}
				cancel()
				if failure == "joined-fault" {
					return errors.Join(request.Err(), fault)
				}
				late = use
				return request.Err()
			}
			err := s.withRequest(request, func(context.Context) error { t.Fatal("a refused request ran work"); return nil })
			if failure == "late-callback" {
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrSyntheticDNSMapping) || s.invalid.Load() || late == nil {
					t.Fatalf("a clean refusal did not finish as a canceled request: %v", err)
				}
				// The owner already returned. This delayed invocation must
				// revoke the source without reaching the closed request body.
				err = late(context.Background())
			}
			if !errors.Is(err, ErrSyntheticDNSMapping) || !s.invalid.Load() || s.ctx.Err() == nil {
				t.Fatalf("source did not fence misconduct: %v", err)
			}
			if failure == "joined-fault" && !errors.Is(err, fault) {
				t.Fatalf("owner fault was lost: %v", err)
			}
		})
	}
}

func TestSyntheticDNSPhaseCallbackContractRefusesBeforeUse(t *testing.T) {
	for _, mode := range []string{"missing", "unbounded", "twice"} {
		t.Run(mode, func(t *testing.T) {
			f := syntheticDNSModelFixture(t, nil)
			owner := &syntheticDNSPhaseModel{phase: context.Background(), mode: mode}
			s := f.source(t, owner)
			calls := 0
			err := s.withRequest(context.Background(), func(context.Context) error { calls++; return nil })
			if !errors.Is(err, ErrSyntheticDNSMapping) {
				t.Fatal("bad phase callback accepted", err)
			}
			if mode == "twice" && calls != 1 || mode != "twice" && calls != 0 {
				t.Fatal("bad callback ran work", calls)
			}
			if err := s.withRequest(context.Background(), func(context.Context) error { t.Fatal("refused phase reopened"); return nil }); err == nil {
				t.Fatal("phase refusal reopened source")
			}
		})
	}
}

type syntheticDNSPhaseEarlyReturnModel struct {
	syntheticDNSPhaseModel
	entered, finish chan struct{}
}

func (o *syntheticDNSPhaseEarlyReturnModel) WithSyntheticRequestPhase(request context.Context, use func(context.Context) error) error {
	go func() { _ = use(request) }()
	<-o.entered
	return nil
}

func TestSyntheticDNSPhaseReturningOwnerRevokesAndJoinsActualCallback(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	owner := &syntheticDNSPhaseEarlyReturnModel{entered: make(chan struct{}), finish: make(chan struct{})}
	s := f.source(t, owner)
	cancelled, returned := make(chan struct{}), make(chan error, 1)
	go func() {
		returned <- s.withRequest(context.Background(), func(c context.Context) error {
			close(owner.entered)
			<-c.Done()
			close(cancelled)
			<-owner.finish
			return nil
		})
	}()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("returning owner did not revoke callback")
	}
	select {
	case <-returned:
		t.Fatal("source returned without joining callback")
	default:
	}
	close(owner.finish)
	if err := <-returned; !errors.Is(err, ErrSyntheticDNSMapping) || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
