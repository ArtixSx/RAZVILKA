//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

var nativeModernCommands = []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel"}

func nativeModernClosedLabel(value string, allowed ...string) string {
	for _, known := range allowed {
		if value == known {
			return known
		}
	}
	return "unavailable"
}

// The helper's public failure Code is already generated from causal labels.
// Re-check that closed vocabulary here rather than copying arbitrary state or
// stdout/stderr into a CI log. Unknown values cannot expose paths or secrets.
func nativeModernClosedFailureCode(value string) string {
	if value == "file-protocol-needs-review" {
		return value
	}
	if len(value) >= 80 {
		return "unavailable"
	}
	actions := []string{"helper", "prepare", "install", "restore", "accept-live", "accept-rollback", "stop-old", "prepare-private", "quiesce", "start-candidate", "stop-candidate", "restore-private", "start-rollback", "resolve", "settle-stopped"}
	boundaries := []string{"action", "source", "review", "previous-review", "journal-open", "journal-current", "journal-order", "install-journal", "file-admission", "quiescence", "authority-control", "authority-guard", "authority-recovery", "authority-provider", "post-authority-control", "post-authority-guard", "post-authority-recovery", "post-authority-provider"}
	reasons := []string{"", "-deadline", "-cancelled", "-review-changed", "-mismatch", "-pending", "-unknown-command", "-retired", "-protocol"}
	for _, stage := range []string{"source", "control-opening", "review-opening", "helper-identity-opening", "old-panel-opening", "panel-absent-opening", "command-root", "command-opening", "receipt-opening", "join-opening", "helper-opening", "supervisor-opening", "child-opening", "caller-opening", "peer-opening", "header-closing", "old-panel-closing", "panel-absent-closing", "control-closing", "facts-closing", "receipt-closing", "context-closing"} {
		reasons = append(reasons, "-ordinary-"+stage)
	}
	for _, action := range actions {
		for _, boundary := range boundaries {
			for _, reason := range reasons {
				if value == "file-protocol-"+action+"-"+boundary+reason {
					return value
				}
			}
		}
	}
	return "unavailable"
}

func nativeModernClosedQuiesce(data []byte) string {
	const prefix = "runtime quiesce refused; category="
	text := string(data)
	if len(data) > 512 || !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, "\n") {
		return "unavailable"
	}
	stage := strings.TrimSuffix(strings.TrimPrefix(text, prefix), "\n")
	if stage == "unknown" || text != updatecheck.RuntimeQuiesceFailureOutput(stage)+"\n" {
		return "unavailable"
	}
	return stage
}

func nativeModernTerminalJob(job updatecheck.Job, id string, helperPID int, helperAbsent bool) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == "" && helperPID > 1 && helperAbsent &&
		job.ID == id && job.HelperPID == helperPID && job.State == "requires-review" && job.Stage == "file-protocol" &&
		!job.CanApply && !job.CanCancel && job.ReviewToken == "" && nativeModernClosedFailureCode(job.Code) != "unavailable"
}

func nativeModernTerminalFailure(t *testing.T, id string, helperPID int) bool {
	t.Helper()
	root, err := ownedfs.Open(installpath.State + "/self-update")
	if err != nil {
		return false
	}
	defer root.Close()
	data, err := root.ReadLimited("current.json", 64<<10)
	if err != nil {
		return false
	}
	defer clear(data)
	var record struct {
		Job updatecheck.Job `json:"job"`
	}
	if json.Unmarshal(data, &record) != nil || !nativeModernTerminalJob(record.Job, id, helperPID, errors.Is(syscall.Kill(helperPID, 0), syscall.ESRCH)) {
		return false
	}
	t.Logf("modern_terminal_failure state=requires-review stage=file-protocol code=%s helper_absent=true", nativeModernClosedFailureCode(record.Job.Code))
	return true // Test failure only: no readiness, cleanup or recovery authority.
}

func nativeModernFailureReceipts(t *testing.T, id string) {
	t.Helper()
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return
	}
	if parent, err := ownedfs.Open(installpath.State + "/self-update"); err == nil {
		data, readErr := parent.ReadLimited("current.json", 64<<10)
		parent.Close()
		var record struct {
			Job updatecheck.Job `json:"job"`
		}
		if readErr == nil && json.Unmarshal(data, &record) == nil && record.Job.ID == id {
			t.Logf("modern_job state=%s stage=%s code=%s", nativeModernClosedLabel(record.Job.State, "preparing", "ready", "installing", "restarting", "requires-review", "completed", "rolled-back", "rolled-back-stopped", "failed", "cancelled", "interrupted"), nativeModernClosedLabel(record.Job.Stage, "preflight", "ready", "handoff", "file-protocol", "completed", "rolled-back", "rolled-back-stopped"), nativeModernClosedFailureCode(record.Job.Code))
		}
		clear(data)
	}
	root, err := ownedfs.Open(installpath.State + "/self-update/" + id)
	if err != nil {
		t.Log("modern_command_diagnostics unavailable")
		return
	}
	defer root.Close()
	quiesce, quiesceErr := root.ReadLimited("quiesce-old-runtime.diagnostic", 512)
	if quiesceErr == nil {
		t.Logf("modern_quiesce category=%s", nativeModernClosedQuiesce(quiesce))
	} else {
		t.Log("modern_quiesce category=unavailable")
	}
	clear(quiesce)
	for _, command := range nativeModernCommands {
		data, err := root.ReadLimited(command+".process.json", 4096)
		var r struct {
			ID         string `json:"id"`
			Command    string `json:"command"`
			State      string `json:"state"`
			WaitECHILD bool   `json:"wait_echild"`
			Cancelled  bool   `json:"cancelled"`
			ExitCode   int    `json:"exit_code"`
		}
		if err != nil || json.Unmarshal(data, &r) != nil || r.ID != id || r.Command != command || r.ExitCode < 0 || r.ExitCode > 255 {
			clear(data)
			t.Logf("modern_command command=%s state=unavailable", command)
			continue
		}
		clear(data)
		t.Logf("modern_command command=%s state=%s wait_echild=%t cancelled=%t exit=%d", command, nativeModernClosedLabel(r.State, "intent", "armed", "running", "runtime-ready", "runtime-handed-off", "not-started", "reaped"), r.WaitECHILD, r.Cancelled, r.ExitCode)
	}
}

func TestNativeModernDiagnosticClosureAndTerminal(t *testing.T) {
	for _, item := range []struct {
		status int
		code   string
		retry  bool
	}{
		{503, "SELF_UPDATE_RECOVERY_REQUIRED", true}, {409, "RESTORE_OPERATION_BUSY", true},
		{503, "RESTORE_OPERATION_BUSY", false}, {409, "SELF_UPDATE_RECOVERY_REQUIRED", false},
		{503, "DATAPLANE_RECOVERY_REQUIRED", false}, {503, "private-token", false}, {200, "", false},
	} {
		if nativeModernReadPending(item.status, item.code) != item.retry {
			t.Fatal("unrelated response entered startup handoff retry")
		}
	}
	for _, value := range []string{"private-token /private/path", "file-protocol-install-action-secret", "file-protocol-secret-source", strings.Repeat("x", 1024)} {
		if nativeModernClosedFailureCode(value) != "unavailable" || nativeModernClosedLabel(value, nativeModernCommands...) != "unavailable" {
			t.Fatal("private value escaped closed diagnostics")
		}
	}
	for _, stage := range []string{"entry", "provider", "manager-platform", "runtime-source-close"} {
		if nativeModernClosedQuiesce([]byte(updatecheck.RuntimeQuiesceFailureOutput(stage)+"\n")) != stage {
			t.Fatal("original closed quiesce category lost")
		}
	}
	for _, text := range []string{"private-token /private/path", "runtime quiesce refused; category=private\n", "runtime quiesce refused; category=provider\nextra\n", "runtime quiesce refused; category=unknown\n", strings.Repeat("x", 513)} {
		if nativeModernClosedQuiesce([]byte(text)) != "unavailable" {
			t.Fatal("arbitrary child output escaped quiesce diagnostics")
		}
	}
	id := strings.Repeat("a", 32)
	job := updatecheck.Job{ID: id, HelperPID: 42, State: "requires-review", Stage: "file-protocol", Code: "file-protocol-install-action-protocol"}
	if !nativeModernTerminalJob(job, id, 42, true) || nativeModernTerminalJob(job, id, 42, false) || nativeModernTerminalJob(job, id, 43, true) || nativeModernTerminalJob(job, strings.Repeat("b", 32), 42, true) {
		t.Fatal("terminal observation lost exact helper/job or process absence")
	}
	for _, state := range []string{"installing", "restarting", "rolled-back", "completed"} {
		changed := job
		changed.State = state
		if nativeModernTerminalJob(changed, id, 42, true) {
			t.Fatal("nonterminal job ended rollback observation")
		}
	}
	for _, field := range []string{"apply", "cancel", "token", "stage", "code"} {
		changed := job
		switch field {
		case "apply":
			changed.CanApply = true
		case "cancel":
			changed.CanCancel = true
		case "token":
			changed.ReviewToken = "private"
		case "stage":
			changed.Stage = "handoff"
		case "code":
			changed.Code = "private"
		}
		if nativeModernTerminalJob(changed, id, 42, true) {
			t.Fatal("incomplete terminal publication ended observation")
		}
	}
}
