package updatecheck

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

const externalOld193InstallerRole = "external-old193-installer"
const bootstrapOfflineAction = "bootstrap-offline"

var ErrInstallerControllerRole = errors.New("self update controller has no current verified installer role")

func bootstrapDecimal(value uint64) string { return strconv.FormatUint(value, 10) }

// Bootstrap review4 has an explicit candidate helper owner. The old executable
// remains the source/rollback image; its bytes never acquire a reader ABI.
type fileBootstrapBinding struct {
	Role          string `json:"role"`
	Mode          string `json:"mode"`
	HelperSHA256  string `json:"helper_sha256"`
	ArchivePath   string `json:"archive_path"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

func validFileReviewOwner(review fileReview, record updateRecord) bool {
	if review.PreparationParent != nil && (review.Schema != selfUpdateProtocolSchema || review.Bootstrap != nil || !validFileProcess(*review.PreparationParent) ||
		review.PreparationParent.PID != record.ParentPID || review.PreparationParent.ExecutableSHA256 != review.OldExecutableSHA256 ||
		!ordinaryFutureVersions(review.OldVersion, review.NewVersion) || !validJournalReaderProof(review.JournalReaders) || review.JournalReaders.RequiredReader != selfupdatejournal.PairedSchema) {
		return false
	}
	if review.Schema == selfUpdateProtocolSchema {
		return review.Bootstrap == nil
	}
	b := review.Bootstrap
	return review.Schema == selfupdatejournal.PairedSchema && b != nil && b.Role == externalOld193InstallerRole && (b.Mode == "live" || b.Mode == "offline") &&
		review.OldVersion == "0.19.3" && b.HelperSHA256 != review.OldExecutableSHA256 && record.Job.Release != nil &&
		validDigest("sha256:"+b.HelperSHA256) && b.HelperSHA256 == strings.TrimPrefix(record.Job.Release.Binary.Digest, "sha256:") &&
		b.HelperSHA256 == record.Files["dist/"+record.Job.Release.Binary.Name] &&
		filepath.IsAbs(b.ArchivePath) && filepath.Clean(b.ArchivePath) == b.ArchivePath &&
		validDigest("sha256:"+b.ArchiveSHA256) && "sha256:"+b.ArchiveSHA256 == record.Job.Release.Archive.Digest && review.JournalReaders == nil
}

func fileInstallAuthority(review fileReview) string {
	if review.Bootstrap != nil && review.Bootstrap.Mode == "offline" {
		return bootstrapOfflineAction
	}
	return "start/live"
}

func fileCommandAuthorityForReview(review fileReview, command string) string {
	if review.Bootstrap != nil && review.Bootstrap.Mode == "offline" {
		switch command {
		case "stop-old-panel", "prepare-private-state", "quiesce-old-runtime":
			return bootstrapOfflineAction
		}
	}
	return fileCommandAuthority(command)
}

func (a *SelfUpdateFileAdapter) checkFileCommandStop(ctx context.Context, id, command string) error {
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	return a.checkStop(ctx, id, fileCommandAuthorityForReview(review, command))
}

// VerifyInstallerControllerRole is a read-only classification for the native
// complete process inventory. A caller cannot supply a role, birth, hash or
// skip list. The fixed adapter rereads the current immutable review and real
// /proc identities, including the observer's own role and the old panel's
// independent inactivity. It supplies no runtime or effect acceptance.
//
// CORE calls it only outside the control lock, for a controller peer found by
// its scanner. Cancellation, an unjoined command, a cold controller, a changed
// review or an unclassified outer parent all refuse. Normal reader2 helpers
// are intentionally ineligible for this first-bootstrap role.
func (a *SelfUpdateFileAdapter) VerifyInstallerControllerRole(ctx context.Context, id string, pid int) error {
	if a == nil || ctx == nil || pid <= 1 {
		return ErrInstallerControllerRole
	}
	if _, finite := ctx.Deadline(); !finite || ctx.Err() != nil {
		return errors.Join(ErrInstallerControllerRole, ctx.Err())
	}
	return a.verifyInstallerControllerRole(ctx, id, pid)
}

// Facts are gathered privately from /proc and the existing journals. This
// predicate has no effect capability and is shared with portable fault tests.
type bootstrapControllerFact struct {
	Process fileProcess
	Parent  int
	Args    []string
}

func bootstrapControllerRole(review fileReview, record updateRecord, identity fileHelperIdentity, command fileCommandReceipt, fact bootstrapControllerFact) string {
	if !validFileReviewOwner(review, record) || record.Owner != updaterOwner || record.Job.ID != review.ID || record.Job.ConfigRevision != review.Revision ||
		record.ExecutableHash != review.OldExecutableSHA256 || record.Job.State != "restarting" || record.Job.ReviewToken != "" || record.Job.CanApply || record.Job.CanCancel ||
		identity.Schema != selfUpdateProtocolSchema || identity.ID != review.ID || !validFileProcess(identity.Process) || !validFileProcess(identity.OldPanel) ||
		identity.Process.Boot != identity.OldPanel.Boot || identity.Process.PID == identity.OldPanel.PID ||
		identity.Process.ExecutableSHA256 != reviewedHelperSHA(review) || identity.OldPanel.ExecutableSHA256 != review.OldExecutableSHA256 ||
		record.Job.HelperPID != identity.Process.PID || record.ParentPID != identity.OldPanel.PID ||
		!validFileProcess(fact.Process) || len(fact.Args) == 0 || fact.Args[0] == "" {
		return ""
	}
	b := review.Bootstrap
	args := fact.Args[1:]
	if fact.Process == identity.Process && len(args) == 4 && args[0] == "self-update-bootstrap-old193" && args[1] == review.ID && args[2] == b.ArchivePath && args[3] == b.ArchiveSHA256 {
		return externalOld193InstallerRole
	}
	if !validFileCommandReceipt(command) || command.ID != review.ID || command.Command != "quiesce-old-runtime" || command.Parent != identity.Process ||
		command.State != "running" || command.Supervisor.ExecutableSHA256 != reviewedHelperSHA(review) || command.Supervisor.PID == identity.Process.PID ||
		command.DirectPID == identity.Process.PID || command.DirectPID == command.Supervisor.PID {
		return ""
	}
	if fact.Process == command.Supervisor && fact.Parent == identity.Process.PID && len(args) == 3 && args[0] == "self-update-command-helper" && args[1] == review.ID && args[2] == "quiesce-old-runtime" {
		return "quiesce-supervisor"
	}
	if fact.Process.PID == command.DirectPID && fact.Process.Boot == command.Supervisor.Boot && fact.Process.ExecutableSHA256 == reviewedHelperSHA(review) && fact.Parent == command.Supervisor.PID &&
		len(args) == 4 && args[0] == "self-update-runtime-quiesce" && args[1] == review.ID && args[2] == bootstrapDecimal(review.Revision) && args[3] == bootstrapDecimal(uint64(command.Supervisor.PID)) {
		return "quiesce-child"
	}
	return ""
}

func reviewedHelperSHA(review fileReview) string {
	if review.Bootstrap != nil {
		return review.Bootstrap.HelperSHA256
	}
	return review.OldExecutableSHA256
}
