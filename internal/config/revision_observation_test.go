package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestRevisionObservationWorksWithoutBorrowingConfigWriterLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	called := false
	if err = s.WithRevisionObservation(context.Background(), s.Get().Revision, func() error { called = true; return nil }); err != nil || !called {
		t.Fatal("independent receipt blocked behind writer lease", called, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("observation changed config", err)
	}
}

func TestRevisionObservationRefusesExternalChangeBeforeAndAfterReceipt(t *testing.T) {
	for _, at := range []string{"before", "after"} {
		t.Run(at, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			s, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := []byte("external replacement")
			if at == "before" {
				if err = os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err = s.WithRevisionObservation(context.Background(), s.Get().Revision, func() error {
				called = true
				return os.WriteFile(path, changed, 0600)
			})
			if !errors.Is(err, ErrRevisionChanged) || called != (at == "after") {
				t.Fatal("external change falsely acknowledged", called, err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, changed) {
				t.Fatal("observation overwrote external change", err)
			}
		})
	}
}

func TestAutonomyEnrollmentHoldsReviewedConfigAcrossJournalPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := store.Get().Revision
	called := false
	publish := func() error {
		called = true
		competing, err := restorejournal.OpenFileTarget(path)
		if competing != nil {
			competing.Close()
			t.Error("config writer admitted during consent publication")
		}
		if !errors.Is(err, restorejournal.ErrBusy) {
			t.Errorf("unexpected competing writer status: %v", err)
		}
		return nil
	}
	held, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WithAutonomyEnrollmentRevision(t.Context(), revision, publish); !errors.Is(err, restorejournal.ErrBusy) || called {
		t.Fatal("sidecar published during competing writer", err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.WithAutonomyEnrollmentRevision(t.Context(), revision, publish); err != nil || !called {
		t.Fatal("same revision could not retry", err)
	}
	called = false
	if err := store.SetSafeMode(!store.Get().SafeMode); err != nil {
		t.Fatal(err)
	}
	if err := store.WithAutonomyEnrollmentRevision(t.Context(), revision, publish); !errors.Is(err, ErrRevisionChanged) || called {
		t.Fatal("old revision authorized sidecar", err)
	}
	if err := os.WriteFile(path, []byte("external replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.WithAutonomyEnrollmentRevision(t.Context(), store.Get().Revision, publish); !errors.Is(err, ErrRevisionChanged) || called {
		t.Fatal("changed file authorized sidecar", err)
	}
}
