package updatecheck

import (
	"context"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// These comparisons preserve saved intent, including a disabled RU snapshot.
// They grant neither a route nor acceptance of a restored runtime. That still
// requires the actual current Store and the routing owner's independent proof.
func filePolicyExclusionsEqual(before, after *config.NetworkPolicy) bool {
	if !config.ResourceExclusionStateEqual(before, after) {
		return false
	}
	var oldClients, newClients config.ClientScope
	if before != nil {
		oldClients = before.Clients
	}
	if after != nil {
		newClients = after.Clients
	}
	return reflect.DeepEqual(oldClients, newClients)
}

func fileConfigExclusionsPreserved(before, after config.Config) bool {
	var oldConsent, newConsent *config.NetworkPolicy
	if before.DefaultRouteConsent != nil {
		oldConsent = before.DefaultRouteConsent.Policy
	}
	if after.DefaultRouteConsent != nil {
		newConsent = after.DefaultRouteConsent.Policy
	}
	return filePolicyExclusionsEqual(before.NetworkPolicy, after.NetworkPolicy) &&
		filePolicyExclusionsEqual(before.AppliedNetworkPolicy, after.AppliedNetworkPolicy) &&
		filePolicyExclusionsEqual(oldConsent, newConsent)
}

func inspectFileMigration(old, staged []byte, revision uint64) (config.Config, error) {
	before, _, err := config.InspectBytes(old)
	if err != nil || before.Revision != revision {
		return config.Config{}, ErrReviewChanged
	}
	after, _, err := config.InspectBytes(staged)
	if err != nil || after.Revision != revision || after.SafeMode || after.ServiceControl.Stopped || !fileConfigExclusionsPreserved(before, after) {
		return config.Config{}, ErrReviewChanged
	}
	return after, nil
}

// Once candidate config is installed, the authoritative prior bytes come from
// the exact reviewed journal image, never from a detached exclusion digest or
// an invented merge. A third current config image is refused by the caller.
func (a *SelfUpdateFileAdapter) configExclusionsCurrent(ctx context.Context, review fileReview, current []byte) error {
	root, err := ownedfs.Open(filepath.Join(a.directory, review.ID))
	if err != nil {
		return err
	}
	defer root.Close()
	staged, err := root.ReadLimited("staged/config.json", 4<<20)
	if err != nil || digestBytes(staged) != review.MigratedConfigSHA256 {
		return ErrReviewChanged
	}
	old := current
	if digestBytes(current) != review.OldConfigSHA256 {
		journal, err := selfupdatejournal.Open(a.installation, a.fileJournal)
		if err != nil {
			return err
		}
		old, _, err = journal.ReviewedConfigImages(ctx, review.ID, review.Files, review.OldExecutableSHA256, review.OldInitSHA256, review.OldConfigSHA256)
		journal.Close()
		if err != nil {
			return err
		}
	}
	if _, err := inspectFileMigration(old, staged, review.Revision); err != nil {
		return err
	}
	return ctx.Err()
}
