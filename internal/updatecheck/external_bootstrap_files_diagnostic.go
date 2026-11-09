package updatecheck

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var externalBootstrapFileStages = []string{
	"journal-open", "prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "prior-check", "prior-seal", "install",
	"offline-authority", "offline-quiescence", "offline-inactivity", "live-start", "live-accept", "live-finish",
	"handoff-source", "handoff-header", "handoff-review", "handoff-identity-seal", "handoff-identity-read", "supervisor-count", "supervisor-join", "final-owner",
	"offline-final-review", "offline-final-authority", "offline-final-quiescence", "offline-final-inactivity", "offline-final-encode", "offline-final-publish",
}

func externalBootstrapFileFailure(stage string, cause error) error {
	code := "refused"
	for _, failure := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{selfupdatejournal.ErrUnknown, "journal-unknown"}, {selfupdatejournal.ErrPending, "journal-pending"}, {selfupdatejournal.ErrMismatch, "journal-mismatch"},
		{ErrFileCommandUnsettled, "command-unsettled"},
		{ErrStrategyStateAdmission, "strategy-state"}, {ErrPairedPriorArchive, "prior-archive"}, {ErrFileProtocol, "file-protocol"},
		{os.ErrNotExist, "missing"}, {os.ErrPermission, "permission"},
	} {
		if errors.Is(cause, failure.err) {
			code = failure.code
			break
		}
	}
	// This existing wrapper keeps a deeper original quiesce category and all
	// errors.Is causes. No raw error/path/output enters the public category.
	return externalBootstrapFailure("files-"+stage+"-"+code, cause)
}

func knownExternalBootstrapFileFailure(category string) bool {
	for _, stage := range externalBootstrapFileStages {
		if code, found := strings.CutPrefix(category, "files-"+stage+"-"); found {
			switch code {
			case "refused", "deadline", "canceled", "journal-unknown", "journal-pending", "journal-mismatch", "command-unsettled", "strategy-state", "prior-archive", "file-protocol", "missing", "permission":
				return true
			}
		}
	}
	return false
}
