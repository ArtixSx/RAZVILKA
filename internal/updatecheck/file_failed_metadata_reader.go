package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Metadata fetch/validation can fail before a release or job directory exists.
// These closed producer headers are readable metadata, not a sealed
// review, file transaction, helper owner or permission to clear retained state.
// Unknown failure codes and any prospective effects retain the ordinary fence.
func (a *SelfUpdateFileAdapter) failedMetadataHeader(ctx context.Context, current updateRecord) (bool, error) {
	if current.Job.State != "failed" && current.Job.State != "cancelled" || current.Job.Stage != "metadata" {
		return false, nil
	}
	_, _, versionOK := parseComparableVersion(current.CurrentVersion)
	if ctx == nil || ctx.Err() != nil || current.Owner != updaterOwner || !jobIDPattern.MatchString(current.Job.ID) ||
		!knownMetadataFailure(current.Job.State, current.Job.Code) || current.Job.Release != nil || current.Job.Downloaded != 0 || current.Job.HelperPID != 0 ||
		current.Job.CanApply || current.Job.CanCancel || current.Job.ReviewToken != "" || current.Job.Attestation || current.Job.Verification != "github-release-sha256" ||
		!ValidChannel(current.Job.Channel) || current.Job.StartedAt.IsZero() || current.Job.UpdatedAt.Before(current.Job.StartedAt) ||
		current.FileReviewSHA256 != "" || current.ExecutableHash != "" || current.Files != nil || current.ParentPID <= 1 ||
		!versionOK || !validDigest("sha256:"+current.ConfigFingerprint) || a.layout == nil || a.layout(current.Deployment) != nil {
		return false, ErrFileProtocol
	}
	// Even an empty own job directory is not this header-before-directory cut.
	if _, err := os.Lstat(filepath.Join(a.directory, current.Job.ID)); !errors.Is(err, os.ErrNotExist) {
		return false, ErrFileProtocol
	}
	return true, ctx.Err()
}

// Keep this list aligned with FetchReleaseChannel/fetchLimited and the prepare
// cancellation owner. Unknown future codes still require a newer reader.
func knownMetadataFailure(state, code string) bool {
	if state == "cancelled" {
		return code == "prepare-cancelled"
	}
	if state != "failed" || code == "prepare-cancelled" {
		return false
	}
	switch code {
	case "unsupported-architecture", "release-url-refused", "official-release-unavailable", "release-response-size-or-read",
		"release-channel-invalid", "release-collection-invalid", "release-channel-empty", "release-not-an-upgrade",
		"release-channel-identity-invalid", "release-identity-invalid", "release-date-invalid", "release-asset-invalid",
		"duplicate-archive", "duplicate-or-large-binary", "release-asset-missing", "prepare-timeout":
		return true
	}
	const prefix = "official-release-http-"
	if strings.HasPrefix(code, prefix) {
		raw := strings.TrimPrefix(code, prefix)
		status, err := strconv.Atoi(raw)
		return err == nil && status >= 100 && status <= 599 && status != 200 && strconv.Itoa(status) == raw
	}
	return false
}
