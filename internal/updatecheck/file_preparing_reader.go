package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

// Preparing is a known read-only producer stage, before Files, ExecutableHash
// and FileReviewSHA256 are published. It grants neither fleet eligibility nor
// retirement; an exact pending-ID inventory still hashes prospective images.
func (a *SelfUpdateFileAdapter) preparingHelper(ctx context.Context, current updateRecord) (bool, error) {
	if current.Job.State != "preparing" {
		return false, nil
	}
	if current.Owner != updaterOwner || !jobIDPattern.MatchString(current.Job.ID) || current.FileReviewSHA256 != "" || current.ExecutableHash != "" || current.Files != nil || current.ParentPID <= 1 || current.Job.HelperPID != 0 || current.Job.CanApply || !current.Job.CanCancel || current.Job.ReviewToken != "" || !ValidChannel(current.Job.Channel) || !validDigest("sha256:"+current.ConfigFingerprint) || current.CurrentVersion == "" || a.layout == nil || a.layout(current.Deployment) != nil {
		return false, ErrFileProtocol
	}
	switch current.Job.Stage {
	case "metadata":
	case "downloading", "verifying", "preflight":
		if current.Job.Release == nil {
			return false, ErrFileProtocol
		}
	default:
		return false, ErrFileProtocol
	}
	path := filepath.Join(a.directory, current.Job.ID)
	entries, err := boundedJobDirectories(path)
	if errors.Is(err, os.ErrNotExist) && current.Job.Stage == "metadata" {
		return true, ctx.Err() // Header publication precedes job-directory creation.
	}
	if err != nil || a.owned == nil || a.owned(path) != nil {
		return false, ErrFileProtocol
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return false, ErrFileProtocol
		}
		switch entry.Name() {
		case "bundle", "staged":
			if !entry.IsDir() {
				return false, ErrFileProtocol
			}
		case "release.tar.gz", "control.bin":
			if !entry.Type().IsRegular() {
				return false, ErrFileProtocol
			}
		case "file-review.json":
			// A completed private review may precede current publication. Only
			// the original active producer can read this exact cut; cold/public
			// readers continue to fence an uncommitted review.
			p := a.ordinaryPreparation
			if p == nil || p.adapter != a || p.reviewSHA == "" || p.lifetime(ctx) != nil || !reflect.DeepEqual(current, p.record) {
				return false, ErrFileProtocol
			}
			root, err := a.commandRoot(current.Job.ID)
			if err != nil {
				return false, err
			}
			data, err := root.ReadLimited(entry.Name(), 256<<10)
			root.Close()
			if err != nil || digestBytes(data) != p.reviewSHA {
				return false, ErrFileProtocol
			}
		default:
			// Sealed review/process/private recovery artifacts without their
			// current digest are an uncommitted cut, not mere preparation.
			return false, ErrFileProtocol
		}
	}
	return true, ctx.Err()
}
