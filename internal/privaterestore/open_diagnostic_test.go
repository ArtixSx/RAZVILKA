package privaterestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Model cancellation after the opening context check, during initial private
// filesystem preparation. No sleep, runtime operation or production test seam.
type openingExpiresContext struct {
	calls int
	cause error
}

func (*openingExpiresContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*openingExpiresContext) Done() <-chan struct{}       { return nil }
func (*openingExpiresContext) Value(any) any               { return nil }
func (c *openingExpiresContext) Err() error {
	c.calls++
	if c.calls > 1 {
		return c.cause
	}
	return nil
}

func TestEmptyPrivateOpeningExpiryKeepsFenceAndAllowsNormalRetry(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			layout := testLayout(t.TempDir())
			coordinator, outcome, err := Open(&openingExpiresContext{cause: cause}, layout)
			if coordinator != nil || outcome != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrRecovery) || !errors.Is(err, cause) {
				t.Fatal("opening expiry lost its fence/cause", outcome, err)
			}
			stage := "journal-recover-deadline"
			if cause == context.Canceled {
				stage = "journal-recover-canceled"
			}
			if !strings.Contains(err.Error(), stage) || strings.Contains(err.Error(), layout.JournalRoot) {
				t.Fatal("unsafe or missing opening stage", err)
			}
			if _, err := os.Stat(filepath.Join(layout.JournalRoot, "restore.private.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("expiry fabricated a journal", err)
			}
			for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.ProviderRoot, layout.StageRoot} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("empty recovery materialized a target", err)
				}
			}
			coordinator, outcome, err = Open(context.Background(), layout)
			if err != nil || outcome != restorejournal.Clean || coordinator == nil {
				t.Fatal("ordinary unchanged retry rejected", outcome, err)
			}
			if err := coordinator.Close(); err != nil {
				t.Fatal(err)
			}
			// A real malformed journal must still refuse, retain exact evidence,
			// and never be mistaken for the earlier empty/expired opening.
			path := filepath.Join(layout.JournalRoot, "restore.private.json")
			original := []byte("private-corrupt-evidence")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			coordinator, outcome, err = Open(context.Background(), layout)
			if coordinator != nil || outcome != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrInvalid) {
				t.Fatal("corrupt evidence accepted", outcome, err)
			}
			retained, readErr := os.ReadFile(path)
			if readErr != nil || string(retained) != string(original) {
				t.Fatal("corrupt evidence changed")
			}
		})
	}
}

func TestOpeningRecoveryDiagnosticIsClosedAndPreservesCauses(t *testing.T) {
	private := errors.New("secret image /private/controller/token")
	for _, test := range []struct {
		cause error
		close bool
		stage string
	}{
		{errors.Join(private, restorejournal.ErrInvalid), false, "journal-recover-invalid"},
		{errors.Join(private, restorejournal.ErrUnavailable), false, "journal-recover-unavailable"},
		{restorejournal.ErrBusy, false, "journal-recover-busy"},
		{restorejournal.ErrAborted, false, "journal-recover-aborted"},
		{private, false, "journal-recover-required"},
		{nil, true, "target-close-required"},
	} {
		err := openingRecoveryError(test.cause, test.close)
		if !errors.Is(err, restorejournal.ErrRecovery) || test.cause != nil && !errors.Is(err, test.cause) || err.Error() != restorejournal.ErrRecovery.Error()+" ("+test.stage+")" {
			t.Fatal("diagnostic changed authority/cause or leaked private data", err)
		}
	}
}
