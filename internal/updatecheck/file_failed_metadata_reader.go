package updatecheck

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Preparation can fail before any controller or immutable review is published.
// These closed producer headers and inert caches are readable metadata, not a sealed
// review, file transaction, helper owner or permission to clear retained state.
// Unknown failure codes and any prospective effects retain the ordinary fence.
func (a *SelfUpdateFileAdapter) failedMetadataHeader(ctx context.Context, current updateRecord) (bool, error) {
	if current.Job.State != "failed" && current.Job.State != "cancelled" {
		return false, nil
	}
	// A sealed owner or later effect stage belongs to the existing immutable
	// review/receipt reader. This classifier must not reject or replace it.
	if current.FileReviewSHA256 != "" || current.ExecutableHash != "" || current.Files != nil {
		return false, nil
	}
	switch current.Job.Stage {
	case "metadata", "downloading", "verifying", "preflight":
	default:
		return false, nil
	}
	_, _, versionOK := parseComparableVersion(current.CurrentVersion)
	if ctx == nil || ctx.Err() != nil || current.Owner != updaterOwner || !jobIDPattern.MatchString(current.Job.ID) ||
		!knownPreparationFailure(current.Job.State, current.Job.Stage, current.Job.Code) || current.Job.HelperPID != 0 ||
		current.Job.CanApply || current.Job.CanCancel || current.Job.ReviewToken != "" || current.Job.Attestation || current.Job.Verification != "github-release-sha256" ||
		!ValidChannel(current.Job.Channel) || current.Job.StartedAt.IsZero() || current.Job.UpdatedAt.Before(current.Job.StartedAt) ||
		current.FileReviewSHA256 != "" || current.ExecutableHash != "" || current.Files != nil || current.ParentPID <= 1 ||
		!versionOK || !validDigest("sha256:"+current.ConfigFingerprint) || a.layout == nil || a.layout(current.Deployment) != nil {
		return false, ErrFileProtocol
	}
	if current.Job.Stage == "metadata" && current.Job.Release == nil {
		if current.Job.Downloaded != 0 || !knownMetadataFailure(current.Job.State, current.Job.Code) {
			return false, ErrFileProtocol
		}
		// Discovery failure before any owned cache was created.
		if _, err := os.Lstat(filepath.Join(a.directory, current.Job.ID)); !errors.Is(err, os.ErrNotExist) {
			return false, ErrFileProtocol
		}
		return true, ctx.Err()
	}
	if !validFailedPreparationRelease(current) || current.Job.Downloaded < 0 || current.Job.Downloaded > current.Job.Release.Archive.Size {
		return false, ErrFileProtocol
	}
	if current.Job.Stage == "metadata" {
		if current.Job.Downloaded != 0 || current.Job.Code != "insufficient-update-space" && current.Job.Code != "prepare-cancelled" && current.Job.Code != "prepare-timeout" {
			return false, ErrFileProtocol
		}
		if _, err := os.Lstat(filepath.Join(a.directory, current.Job.ID)); !errors.Is(err, os.ErrNotExist) {
			return false, ErrFileProtocol
		}
		return true, ctx.Err()
	}
	if (current.Job.Stage == "verifying" || current.Job.Stage == "preflight") && current.Job.Downloaded != current.Job.Release.Archive.Size {
		return false, ErrFileProtocol
	}
	return true, a.inertPreparationCache(ctx, current)

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

// Recognize only current producer failures. Neither an arbitrary error string
// nor a terminal label permits ignoring a process, private state or controller.
func knownPreparationFailure(state, stage, code string) bool {
	if state == "cancelled" {
		return code == "prepare-cancelled" && (stage == "metadata" || stage == "downloading" || stage == "verifying" || stage == "preflight")
	}
	if state != "failed" {
		return false
	}
	if code == "prepare-timeout" {
		return stage == "metadata" || stage == "downloading" || stage == "verifying" || stage == "preflight"
	}
	switch stage {
	case "metadata":
		return code == "insufficient-update-space" || knownMetadataFailure(state, code)
	case "downloading":
		if knownMetadataFailure(state, code) && (code == "release-url-refused" || code == "official-release-unavailable" || strings.HasPrefix(code, "official-release-http-")) {
			return true
		}
		switch code {
		case "asset-size-or-digest-invalid", "asset-length-changed", "asset-too-large", "asset-download-interrupted", "asset-sha256-mismatch":
			return true
		}
	case "verifying":
		switch code {
		case "archive-gzip-invalid", "archive-tar-invalid", "archive-entry-refused", "archive-root-refused", "archive-link-or-special-entry", "archive-file-size-refused", "archive-write-failed", "archive-expanded-limit", "archive-gzip-footer-or-limit", "archive-required-file-missing", "archive-binary-digest-mismatch", "binary-architecture-invalid", "binary-manifest-mismatch", "binary-manifest-missing", "prepared-files-invalid", "prepared-file-invalid", "prepared-file-changed":
			return true
		}
	case "preflight":
		switch code {
		case "candidate-version-or-architecture-refused", "installer-preflight-self-update-schema-refused", "installer-preflight-self-update-metadata-refused", "installer-preflight-node-history-refused", "installer-preflight-autonomy-refused", "installer-preflight-refused", "ordinary-preparation-owner-refused", "ordinary-preparation-version-refused", "ordinary-preparation-histories-refused", "ordinary-preparation-capabilities-refused", "ordinary-preparation-journals-refused", "ordinary-preparation-candidate-check-refused", "ordinary-preparation-script-syntax-refused":
			return true
		}
	}
	return false
}

func validFailedPreparationRelease(c updateRecord) bool {
	r := c.Job.Release
	if r == nil || r.ID <= 0 || !supportedArchitecture(r.Architecture) || r.Version != strings.TrimPrefix(r.Tag, "v") || !CanUpgradeChannel(c.CurrentVersion, r.Tag, c.Job.Channel) || r.Page != "https://github.com/"+officialRepository+"/releases/tag/"+r.Tag {
		return false
	}
	if _, err := time.Parse(time.RFC3339, r.PublishedAt); err != nil {
		return false
	}
	for i, a := range []Asset{r.Archive, r.Binary} {
		name := "RAZVILKA-" + r.Version + "-entware.tar.gz"
		max := MaximumArchiveBytes
		if i == 1 {
			name = "razvilka-linux-" + r.Architecture
			max = MaximumBinaryBytes
		}
		if a.ID <= 0 || a.Name != name || a.Size <= 0 || a.Size > max || !validDigest(a.Digest) || a.URL != "https://github.com/"+officialRepository+"/releases/download/"+r.Tag+"/"+name {
			return false
		}
	}
	return true
}

// Only inert archive/partial extraction bytes can survive an unsealed failure.
// Bound names, count and size; never follow links or admit a staged executable,
// private snapshot, command receipt, helper, review or unknown future artifact.
func (a *SelfUpdateFileAdapter) inertPreparationCache(ctx context.Context, c updateRecord) error {
	jobPath := filepath.Join(a.directory, c.Job.ID)
	if a.owned == nil || a.owned(jobPath) != nil {
		return ErrFileProtocol
	}
	root, err := ownedfs.Open(jobPath)
	if err != nil {
		return ErrFileProtocol
	}
	defer root.Close()
	initial, err := root.RootInfo()
	if err != nil {
		return err
	}
	allowed := map[string]int64{"release.tar.gz": c.Job.Release.Archive.Size}
	dirs := map[string]bool{".": true}
	if c.Job.Stage != "downloading" {
		for name, maximum := range requiredInstallFiles(*c.Job.Release) {
			name = filepath.Join("bundle", filepath.FromSlash(name))
			allowed[name] = maximum
			for dir := filepath.Dir(name); dir != "."; dir = filepath.Dir(dir) {
				dirs[dir] = true
			}
		}
	}
	count := 0
	observed := map[string]os.FileInfo{}
	var visit func(string) error
	visit = func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.RootInfo()
		if name != "." {
			info, err = root.Stat(name)
		}
		if err != nil {
			return err
		}
		if a.owned(filepath.Join(jobPath, name)) != nil {
			return ErrFileProtocol
		}
		observed[name] = info
		if info.IsDir() {
			if !dirs[name] {
				return ErrFileProtocol
			}
			// Read the descendant through the held root. A pathname swap must
			// not redirect enumeration to an unrelated absolute directory.
			var entries []os.DirEntry
			if name == "." {
				entries, err = root.ReadDir(33)
			} else {
				entries, err = root.ReadDirAt(name, 33)
			}
			if err != nil {
				return err
			}

			for _, entry := range entries {
				count++
				if count > 32 || entry.Type()&os.ModeSymlink != 0 {
					return ErrFileProtocol
				}
				if err := visit(filepath.Join(name, entry.Name())); err != nil {
					return err
				}
			}
		} else if maximum, ok := allowed[name]; !ok || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
			return ErrFileProtocol
		}
		return nil
	}
	if err := visit("."); err != nil {
		return err
	}
	// Recheck every observed identity and directory generation. A child
	// replacement/addition during enumeration invalidates this observation.
	for name, before := range observed {
		after, err := root.RootInfo()
		if name != "." {
			after, err = root.Stat(name)
		}
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return ErrFileProtocol
		}
	}
	after, err := os.Lstat(jobPath)
	if err != nil || !os.SameFile(initial, after) {
		return ErrFileProtocol
	}
	return ctx.Err()
}
