package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestOriginalRecordCloseFailureRetainsAcceptedWriterAndStickyFailure(t *testing.T) {
	_, e := retainedNFQWSProbeScopeFixture(t)
	d := e.records
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := d.beforePublication(); err != nil {
		t.Fatal(err)
	}
	old := d.files[0]
	// Actual descriptor close after the original opening, before the writer
	// replaces it. The sink's second Close must report the real OS error.
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(d.scope.execution)
	if err != nil {
		t.Fatal(err)
	}
	err = d.publishOriginalDurable(0, data, syncDataplaneJournalDirectory)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatal("original close error lost", err)
	}
	accepted := d.files[0]
	if accepted == nil || accepted == old {
		t.Fatal("new authored FD not retained")
	}
	info, err := accepted.Stat()
	if err != nil {
		t.Fatal("accepted FD closed", err)
	}
	if !errors.Is(d.current(ctx, false), os.ErrClosed) || !errors.Is(d.beforePublication(), os.ErrClosed) {
		t.Fatal("ambiguous close became usable proof")
	}
	if !errors.Is(d.publishOriginalDurable(0, data, syncDataplaneJournalDirectory), os.ErrClosed) {
		t.Fatal("sticky failure was reset")
	}
	if after, err := accepted.Stat(); err != nil || !os.SameFile(info, after) {
		t.Fatal("refused retry lost original writer", err)
	}
	first := d.close()
	if !errors.Is(first, os.ErrClosed) || d.close() != first {
		t.Fatal("repeated close erased original failure", first)
	}
	if _, err := accepted.Stat(); err == nil {
		t.Fatal("owned new descriptor leaked", err)
	}
}
