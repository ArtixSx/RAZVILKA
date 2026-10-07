package dataplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNFQWSActiveHelperTransferIsOneUseAndDurableBeforeACK(t *testing.T) {
	l, _, base := nfqws2ActiveRunningFixture(t)
	tr := &nfqws2ActiveModelTransport{}
	for _, kind := range []string{"permit", "transfer", "finalize"} {
		f := base
		f.Kind = kind
		if kind != "permit" {
			f.Child = l.Child
		}
		tr.frames = append(tr.frames, f)
	}
	h := &nfqws2ActiveHelperProtocol{transport: tr, command: l.Command, base: base}
	ctx := context.Background()
	begins := 0
	if h.ready() != nil || h.admit(ctx, func() error { return nil }, func() error { begins++; return nil }) != nil || h.started(l.Child) != nil {
		t.Fatal("one-use helper start failed")
	}
	durable := []string{}
	if err := h.transfer(ctx, func() error { return nil }, func(phase string) error {
		// Each callback precedes its corresponding emitted ACK.
		if len(tr.sent) != 2+len(durable) {
			t.Fatal("helper ACK emitted before durable phase")
		}
		durable = append(durable, phase)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if begins != 1 || !reflect.DeepEqual(durable, []string{"provisional", "final"}) || h.phase != 4 || len(tr.sent) != 4 {
		t.Fatal("helper phase sequence changed")
	}
	if h.admit(ctx, func() error { return nil }, func() error { begins++; return nil }) == nil || h.transfer(ctx, func() error { return nil }, func(string) error { return nil }) == nil || begins != 1 {
		t.Fatal("live helper invocation replayed")
	}
}

func TestNFQWSActiveHelperLostOrForeignFinalNeverCompletes(t *testing.T) {
	for _, which := range []string{"foreign-binding", "provisional-as-final", "missing-final", "durable-provisional-failed", "durable-final-failed", "cancel-before-final"} {
		t.Run(which, func(t *testing.T) {
			l, _, base := nfqws2ActiveRunningFixture(t)
			transfer, final := base, base
			transfer.Kind, transfer.Child = "transfer", l.Child
			final.Kind, final.Child = "finalize", l.Child
			tr := &nfqws2ActiveModelTransport{frames: []nfqws2ActiveFrame{transfer, final}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch which {
			case "foreign-binding":
				tr.frames[1].Binding.SessionID = "foreign"
			case "provisional-as-final":
				tr.frames[1].Kind = "transfer"
			case "missing-final":
				tr.frames = tr.frames[:1]
			}
			h := &nfqws2ActiveHelperProtocol{transport: tr, command: l.Command, base: base, child: l.Child, phase: 3}
			err := h.transfer(ctx, func() error { return nil }, func(phase string) error {
				if which == "durable-provisional-failed" && phase == "provisional" || which == "durable-final-failed" && phase == "final" {
					return ErrReviewChanged
				}
				if which == "cancel-before-final" && phase == "provisional" {
					cancel()
				}
				return nil
			})
			if err == nil || h.phase != -1 {
				t.Fatal("failed final became active")
			}
			for _, f := range tr.sent {
				if f.Kind == "active" {
					t.Fatal("unconfirmed helper emitted active ACK")
				}
			}
			if h.transfer(ctx, func() error { return nil }, func(string) error { return nil }) == nil {
				t.Fatal("failed helper transfer replayed")
			}
		})
	}
}

func TestNFQWSActiveOnceRemembersSwallowedFailureAndSealsCallback(t *testing.T) {
	for _, which := range []string{"duplicate", "panic", "begin-error", "not-called"} {
		t.Run(which, func(t *testing.T) {
			calls := 0
			var retained func() error
			s := &nfqws2ActiveOnce{open: true, begin: func() error {
				calls++
				if which == "panic" {
					panic("private")
				}
				if which == "begin-error" {
					return ErrReviewChanged
				}
				return nil
			}}
			err := s.invoke(func(f func() error) (err error) {
				retained = f
				defer func() { _ = recover() }()
				if which != "not-called" {
					_ = f()
				}
				if which == "duplicate" {
					_ = f()
				}
				return nil
			})
			if !errors.Is(err, ErrNFQWSManagedProcessUnknown) && which != "begin-error" {
				t.Fatal("swallowed invalid invocation accepted", err)
			}
			if which == "begin-error" && !errors.Is(err, ErrReviewChanged) {
				t.Fatal("begin failure swallowed")
			}
			before := calls
			if retained() == nil || calls != before {
				t.Fatal("retained callback replayed after sealing")
			}
		})
	}
}
