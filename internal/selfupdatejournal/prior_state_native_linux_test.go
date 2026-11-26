//go:build linux

package selfupdatejournal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPreparedPriorStateRefusesSubstitutedWriterDuringCopy(t *testing.T) {
	f := preparedPriorFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	marker := filepath.Join(f.journal, ".writer.lock")
	err := f.store.WithPreparedPriorState(ctx, transaction, okay, okay, func(context.Context, Receipt) error {
		data, err := os.ReadFile(marker)
		if err != nil {
			return err
		}
		if err := os.Rename(marker, filepath.Join(f.journal, "foreign-writer-evidence")); err != nil {
			return err
		}
		return os.WriteFile(marker, data, 0600)
	})
	if err == nil {
		t.Fatal("copy retained authority from a detached writer inode")
	}
	if _, err := os.Stat(filepath.Join(f.journal, "foreign-writer-evidence")); err != nil {
		t.Fatal("refusal erased substituted writer evidence", err)
	}
}
