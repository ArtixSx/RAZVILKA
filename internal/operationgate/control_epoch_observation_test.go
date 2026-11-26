package operationgate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestControlEpochReadObservationGrantsNoOperationAndStopRevokes(t *testing.T) {
	_, _, r, path := epochReviewFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.ObserveCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.WithStart(ctx, func() error { t.Fatal("read observation granted a launch"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(context.Background(), path, controlTestID, 7); err != nil {
		t.Fatal(err)
	}
	if err := r.ObserveCurrent(ctx); !errors.Is(err, ErrSelfUpdateStopped) {
		t.Fatal("Stop kept prior evidence current", err)
	}
	if err := r.ObserveCurrent(context.Background()); err == nil {
		t.Fatal("unbounded observation")
	}
	copy := ControlEpochReview{self: r}
	if err := copy.ObserveCurrent(ctx); err == nil {
		t.Fatal("copied retained owner")
	}
}
