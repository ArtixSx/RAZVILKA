package dnscontrol

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Explicit phase model: the Gate and source are actual, while this test owner
// retains the admitted original context in place of Manager's private carrier.
type syntheticDNSPhaseModel struct {
	phase context.Context
	mode  string
}

func (*syntheticDNSPhaseModel) WithSyntheticPublication(context.Context, *SyntheticDNSMapping, func(context.Context) error) error {
	return ErrSyntheticDNSMappingRequired
}
func (*syntheticDNSPhaseModel) CurrentSyntheticMapping(context.Context, *SyntheticDNSMapping) error {
	return ErrSyntheticDNSMappingRequired
}
func (o *syntheticDNSPhaseModel) WithSyntheticRequestPhase(request context.Context, use func(context.Context) error) error {
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
