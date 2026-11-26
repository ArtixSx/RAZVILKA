package operationgate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestControlEpochDNSReplyRequiresOriginalFiniteOperationAndLeaf(t *testing.T) {
	_, original, review, _ := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, time.Second)
	defer cancel()
	foreign := &Gate{}
	other, release, err := foreign.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	otherBounded, cancelOther := context.WithTimeout(other, time.Second)
	defer cancelOther()
	raw, cancelRaw := context.WithTimeout(context.Background(), time.Second)
	defer cancelRaw()
	canceled, cancelRequest := context.WithCancel(ctx)
	cancelRequest()
	for _, test := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"unbounded", original, ErrSelfUpdateStopChanged},
		{"raw", raw, ErrBusy},
		{"foreign", otherBounded, ErrBusy},
		{"canceled", canceled, context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := review.WithDNSReply(test.ctx, func(write func() error) error { return write() }, func() error { t.Fatal("invalid operation wrote"); return nil })
			if !errors.Is(err, test.want) {
				t.Fatal(err)
			}
		})
	}
	observe := func(write func() error) error { return write() }
	if err := review.WithDNSReply(ctx, nil, func() error { return nil }); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("missing observation", err)
	}
	if err := review.WithDNSReply(ctx, observe, nil); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("missing prepared socket", err)
	}
	copy := &ControlEpochReview{self: review.self, gate: review.gate, dir: review.dir, lock: review.lock, info: review.info, ref: review.ref}
	if err := copy.WithDNSReply(ctx, observe, func() error { t.Fatal("copied owner wrote"); return nil }); !errors.Is(err, ErrSelfUpdateStopChanged) {
		t.Fatal("copied owner", err)
	}
}

func TestControlEpochDNSReplyRejectsLateDuplicateAndSwallowedWriteFailure(t *testing.T) {
	_, original, review, _ := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, time.Second)
	defer cancel()
	writes := 0
	var late func() error
	err := review.WithDNSReply(ctx, func(write func() error) error { late = write; return nil }, func() error { writes++; return nil })
	if !errors.Is(err, ErrSelfUpdateStopChanged) || !errors.Is(late(), ErrSelfUpdateStopChanged) || writes != 0 {
		t.Fatal("missing/escaped observation wrote", writes, err)
	}
	err = review.WithDNSReply(ctx, func(write func() error) error { _ = write(); _ = write(); return nil }, func() error { writes++; return nil })
	if !errors.Is(err, ErrSelfUpdateStopChanged) || writes != 1 {
		t.Fatal("duplicate write escaped", writes, err)
	}
	failure := errors.New("local socket failure")
	err = review.WithDNSReply(ctx, func(write func() error) error { _ = write(); return nil }, func() error { return failure })
	if !errors.Is(err, failure) {
		t.Fatal("observation swallowed write failure", err)
	}
	if err := review.Current(ctx); err != nil {
		t.Fatal("local write failure invalidated control owner", err)
	}
}

func TestControlEpochDNSReplyObserverPanicRevokesRetainedWrite(t *testing.T) {
	root := controlTestRoot(t)
	if _, err := InitializeSelfUpdateControl(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	gate := &Gate{}
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, err := gate.ExclusiveContext(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	review, err := gate.ReviewControlEpoch(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer review.Close()
	var retained func() error
	writes := 0
	panicValue := "observation panicked"
	func() {
		defer func() {
			if value := recover(); value != panicValue {
				t.Fatal("observer panic changed or swallowed", value)
			}
		}()
		_ = review.WithDNSReply(ctx, func(write func() error) error {
			retained = write
			panic(panicValue)
		}, func() error { writes++; return nil })
	}()
	release()
	if retained == nil || !errors.Is(retained(), ErrSelfUpdateStopChanged) || writes != 0 {
		t.Fatal("retained write survived observer panic", writes)
	}
	if release, err := gate.Enter(context.Background()); err != nil {
		t.Fatal("panic retained original Gate use", err)
	} else {
		release()
	}
}

func TestControlEpochDNSReplyDurableStopBeforeWriteRefuses(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, time.Second)
	defer cancel()
	err := review.WithDNSReply(ctx, func(write func() error) error {
		if _, err := RequestSelfUpdateStop(ctx, root, controlTestID, 7); err != nil {
			t.Fatal(err)
		}
		return write()
	}, func() error { t.Fatal("socket write after durable Stop"); return nil })
	if !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
}

func TestControlEpochDNSReplySerializesOnlyPreparedWriteWithStop(t *testing.T) {
	_, original, review, root := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(original, 2*time.Second)
	defer cancel()
	entered, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	// A bounded blocking local write model proves lock ordering. Actual ephemeral
	// UDP/TCP socket publication is covered in dnscontrol listener tests.
	go func() {
		result <- review.WithDNSReply(ctx, func(write func() error) error { return write() }, func() error {
			close(entered)
			select {
			case <-finish:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("prepared write not entered")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err := RequestSelfUpdateStop(stopCtx, root, controlTestID, 7)
	stopCancel()
	close(finish)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Stop overlapped prepared socket write", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(ctx, root, controlTestID, 7); err != nil {
		t.Fatal("socket write retained control lock", err)
	}
	if err := review.WithDNSReply(ctx, func(write func() error) error { return write() }, func() error { t.Fatal("post-Stop write"); return nil }); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal(err)
	}
}
