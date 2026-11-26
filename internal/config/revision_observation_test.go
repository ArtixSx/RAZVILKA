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
