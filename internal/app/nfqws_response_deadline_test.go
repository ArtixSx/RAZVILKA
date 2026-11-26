package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type managedNFQDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadline time.Time
	err      error
}

func (w *managedNFQDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return w.err
}

func TestManagedNFQResponseDeadlineUsesFiniteCallerAndRefusesUnsupportedTransport(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	ctx, finish := managedNFQRuntimeCallContext(parent, "start")
	defer finish()
	deadline, _ := parent.Deadline()
	w := &managedNFQDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := managedNFQResponseDeadline(w, ctx); err != nil || w.deadline != deadline.Add(managedNFQResponseGrace) {
		t.Fatal("response window lost original parent bound", w.deadline, err)
	}
	wrapped := &auditResponseWriter{ResponseWriter: w}
	w.deadline = time.Time{}
	if err := managedNFQResponseDeadline(wrapped, ctx); err != nil || w.deadline != deadline.Add(managedNFQResponseGrace) || wrapped.status != 0 {
		t.Fatal("audited request lost transport access or wrote a response", err)
	}
	if err := managedNFQResponseDeadline(httptest.NewRecorder(), ctx); !errors.Is(err, http.ErrNotSupported) {
		t.Fatal("unsupported response transport silently claimed long budget", err)
	}
	w.deadline = time.Time{}
	if err := managedNFQResponseDeadline(w, context.Background()); err == nil || !w.deadline.IsZero() {
		t.Fatal("unbounded communication window granted", err)
	}
	cancel()
	if err := managedNFQResponseDeadline(w, ctx); !errors.Is(err, context.Canceled) || !w.deadline.IsZero() {
		t.Fatal("canceled caller acquired another window", err)
	}
}
