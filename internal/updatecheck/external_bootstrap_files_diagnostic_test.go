package updatecheck

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func TestExternalBootstrapFileDiagnosticPreservesSpecificCause(t *testing.T) {
	for _, stage := range externalBootstrapFileStages {
		for _, tc := range []struct {
			cause error
			code  string
		}{
			{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"}, {selfupdatejournal.ErrUnknown, "journal-unknown"},
			{selfupdatejournal.ErrPending, "journal-pending"}, {selfupdatejournal.ErrMismatch, "journal-mismatch"},
			{ErrFileCommandUnsettled, "command-unsettled"},
			{ErrStrategyStateAdmission, "strategy-state"}, {ErrPairedPriorArchive, "prior-archive"}, {ErrFileProtocol, "file-protocol"},
			{errors.New("private path/secret/output"), "refused"},
		} {
			err := externalBootstrapFileFailure(stage, tc.cause)
			want := "files-" + stage + "-" + tc.code
			if !errors.Is(err, tc.cause) || !errors.Is(err, ErrExternalBootstrap) || ExternalBootstrapFailureCategory(err) != want || !ExternalBootstrapFailureCategoryKnown(want) {
				t.Fatal("stage/cause lost", stage, tc.code)
			}
		}
	}
	original := externalBootstrapFailure("quiesce-runtime-inactivity-deadline-scoped-dns-dns-observation-proc-closing-proc.installer-role-close", context.DeadlineExceeded)
	wrapped := externalBootstrapFileFailure("quiesce-old-runtime", original)
	if ExternalBootstrapFailureCategory(wrapped) != ExternalBootstrapFailureCategory(original) || !errors.Is(wrapped, context.DeadlineExceeded) {
		t.Fatal("original specific observation replaced")
	}
	for _, category := range []string{"files-unknown-file-protocol", "files-prepare-secret", "files-install-missing\nprivate", "files-prior-seal-file-protocol-extra"} {
		if ExternalBootstrapFailureCategoryKnown(category) {
			t.Fatal("unbounded diagnostic admitted", category)
		}
	}
	if got := ExternalBootstrapFailureCategory(externalBootstrapFileFailure("unknown", ErrFileProtocol)); got != "external-bootstrap-refused" {
		t.Fatal("unrecognized stage escaped", got)
	}
}
