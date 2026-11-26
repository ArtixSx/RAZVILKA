package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func TestSelfUpdateFileFailureClosedCodesPreserveCause(t *testing.T) {
	private := errors.New("private /opt/secret path; stderr=do-not-persist")
	for _, test := range []struct {
		name, action, boundary, want string
		cause                        error
	}{
		{"boundary", "quiesce-old-runtime", "post-authority-provider", "file-protocol-quiesce-post-authority-provider", private},
		{"deadline", "install", "quiescence", "file-protocol-install-quiescence-deadline", errors.Join(private, context.DeadlineExceeded)},
		{"cancelled", "install", "authority-guard", "file-protocol-install-authority-guard-cancelled", context.Canceled},
		{"review", "install", "review", "file-protocol-install-review-review-changed", ErrReviewChanged},
		{"mismatch", "install", "journal-current", "file-protocol-install-journal-current-mismatch", selfupdatejournal.ErrMismatch},
		{"pending", "install", "journal-order", "file-protocol-install-journal-order-pending", selfupdatejournal.ErrPending},
		{"unknown", "quiesce-old-runtime", "action", "file-protocol-quiesce-action-unknown-command", selfupdatejournal.ErrUnknown},
		{"retired", "install", "install-journal", "file-protocol-install-install-journal-retired", selfupdatejournal.ErrRetired},
		{"protocol", "install", "review", "file-protocol-install-review-protocol", ErrFileProtocol},
		{"ordinary", "install", "quiescence", "file-protocol-install-quiescence-ordinary-command-opening", ordinaryInstallerRoleAt("command-opening", private)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := SelfUpdateFileFailureAt(test.action, test.boundary, test.cause)
			if !errors.Is(err, test.cause) {
				t.Fatal("annotation lost actual cause")
			}
			code := SelfUpdateFileFailureCode(fmt.Errorf("outer private stderr: %w", err))
			if code != test.want || len(code) >= 80 || !errorCodePattern.MatchString(code) {
				t.Fatal("unexpected closed code", code, test.want)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(code, "private /opt") || strings.Contains(code, "stderr") {
				t.Fatal("raw diagnostic text escaped")
			}
		})
	}
}

func TestSelfUpdateFileFailureInnerBoundaryAndFirstBranch(t *testing.T) {
	first := SelfUpdateFileFailureAt("install", "quiescence", ordinaryInstallerRoleAt("command-opening", nil))
	first = SelfUpdateFileFailureAt("install", "install-journal", first)
	first = SelfUpdateFileFailureAt("install", "action", first)
	second := SelfUpdateFileFailureAt("restore", "authority-guard", context.Canceled)
	if got := SelfUpdateFileFailureCode(errors.Join(first, second)); got != "file-protocol-install-quiescence-ordinary-command-opening" {
		t.Fatal("outer annotation or later branch replaced original boundary", got)
	}
	if !errors.Is(first, ErrOrdinaryInstallerControllerRole) {
		t.Fatal("ordinary role sentinel was lost")
	}
}

type fileProtocolCycle struct{}

func (e *fileProtocolCycle) Error() string { return "private cyclic cause" }
func (e *fileProtocolCycle) Unwrap() error { return e }

func TestSelfUpdateFileFailureUnknownAndBoundedFallback(t *testing.T) {
	private := errors.New("file-protocol-forged-code")
	var typedNil *fileProtocolFailure
	for _, err := range []error{
		nil, private, typedNil,
		SelfUpdateFileFailureAt("untrusted", "quiescence", private),
		SelfUpdateFileFailureAt("install", "untrusted", private),
		&fileProtocolFailure{"untrusted", "quiescence", private},
		SelfUpdateFileFailureAt("install", "quiescence", &fileProtocolCycle{}),
	} {
		if got := SelfUpdateFileFailureCode(err); got != fileProtocolNeedsReview {
			t.Fatal("unknown error became a diagnostic code", got)
		}
	}
	if SelfUpdateFileFailureAt("install", "quiescence", nil) != nil || SelfUpdateFileFailureAt("untrusted", "quiescence", private) != private {
		t.Fatal("success or unknown annotations changed the result")
	}
	deep := SelfUpdateFileFailureAt("install", "quiescence", context.Canceled)
	for i := 0; i < 65; i++ {
		deep = fmt.Errorf("private wrapper: %w", deep)
	}
	wide := make([]error, 65)
	for i := range wide {
		wide[i] = private
	}
	for _, err := range []error{deep, SelfUpdateFileFailureAt("install", "quiescence", errors.Join(wide...))} {
		if got := SelfUpdateFileFailureCode(err); got != fileProtocolNeedsReview {
			t.Fatal("error traversal exceeded its fixed budget", got)
		}
	}
}

func TestSelfUpdateFileFailureCodesFitExistingRecord(t *testing.T) {
	actions := []string{"helper", "prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "start-candidate-panel", "accept-live", "stop-candidate-panel", "restore", "restore-private-state", "start-rollback-panel", "accept-rollback", "resolve-unknown", "settle-stopped-rollback"}
	boundaries := []string{"action", "source", "review", "previous-review", "journal-open", "journal-current", "journal-order", "install-journal", "file-admission", "quiescence", "authority-control", "authority-guard", "authority-recovery", "authority-provider", "post-authority-control", "post-authority-guard", "post-authority-recovery", "post-authority-provider"}
	for _, action := range actions {
		for _, boundary := range boundaries {
			err := SelfUpdateFileFailureAt(action, boundary, ordinaryInstallerRoleAt("helper-identity-opening", nil))
			code := SelfUpdateFileFailureCode(err)
			if len(code) >= 80 || !errorCodePattern.MatchString(code) || code == fileProtocolNeedsReview {
				t.Fatal("known code violates existing convention", action, boundary, code)
			}
		}
	}
	code := SelfUpdateFileFailureCode(SelfUpdateFileFailureAt("install", "quiescence", ordinaryInstallerRoleAt("command-opening", nil)))
	id := strings.Repeat("a", 32)
	record := updateRecord{Owner: updaterOwner, FileReviewSHA256: strings.Repeat("b", 64), Job: Job{ID: id, State: "requires-review", Stage: "file-protocol", Code: code, Release: &Release{}}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded updateRecord
	if err := decodeFileProtocol(data, &decoded); err != nil || decoded.Job.Code != code || decoded.Job.CanApply || decoded.Job.CanCancel {
		t.Fatal("existing canonical record refused diagnostic data", err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "current.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if actual, err := readAdapterRecord(directory, id); err != nil || actual.Job.Code != code {
		t.Fatal("existing adapter reader refused diagnostic data", err)
	}
	u := &Updater{Directory: directory}
	if job := u.Snapshot(); job.Code != code || job.State != "requires-review" || job.CanApply || job.CanCancel {
		t.Fatal("existing helper status reader changed the outcome", job)
	}
}
