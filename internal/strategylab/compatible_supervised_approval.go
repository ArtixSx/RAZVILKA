package strategylab

import (
	"errors"
	"slices"
)

// CompatibilityApprovedAsset describes bytes approved by the installation owner.
// Its digest must come from that review, rather than local discovery at launch.
type CompatibilityApprovedAsset struct {
	Path   string
	SHA256 string
}

// CompatibilityApproval is explicit owner-reviewed installation evidence. A
// local hash, or an untrusted request carrying these fields, cannot create it.
// The supervised launcher also requires protected Linux paths before use.
type CompatibilityApproval struct {
	BinaryPath     string
	BinarySHA256   string
	Assets         []CompatibilityApprovedAsset
	BaseArguments  []string
	ControlPath    string
	InstallationID string
	Sequence       uint64
}

func compatibilityReviewApproved(approval CompatibilityApproval) (compatibilityReview, error) {
	if len(approval.Assets) > compatibilityMaxFiles || len(approval.BaseArguments) == 0 || len(approval.BaseArguments) > compatibilityMaxFiles {
		return compatibilityReview{}, errors.New("compatibility approval exceeds its reviewed file/base bounds")
	}
	// Freeze caller-owned slices before constructing the immutable review.
	approval.Assets = slices.Clone(approval.Assets)
	approval.BaseArguments = slices.Clone(approval.BaseArguments)
	review := compatibilityReview{
		Binary: compatibilityFileBinding{
			Path: approval.BinaryPath, SHA256: approval.BinarySHA256, Size: 1,
		},
		BaseArguments: approval.BaseArguments, ControlPath: approval.ControlPath,
		InstallationID: approval.InstallationID, Sequence: approval.Sequence,
	}
	for _, asset := range approval.Assets {
		review.Assets = append(review.Assets, compatibilityFileBinding{Path: asset.Path, SHA256: asset.SHA256, Size: 1})
	}
	// Placeholder sizes permit validation of the explicit declaration only. No
	// review is returned until actual bounded file bytes match every digest.
	if err := validateCompatibilityReview(review); err != nil {
		return compatibilityReview{}, err
	}
	binary, assets, err := compatibilityCaptureFiles(approval.BinaryPath, approval.BaseArguments)
	if err != nil {
		return compatibilityReview{}, err
	}
	if binary.SHA256 != approval.BinarySHA256 || len(assets) != len(approval.Assets) {
		return compatibilityReview{}, errors.New("compatibility files do not match explicit owner approval")
	}
	for i, asset := range assets {
		if asset.Path != approval.Assets[i].Path || asset.SHA256 != approval.Assets[i].SHA256 {
			return compatibilityReview{}, errors.New("compatibility assets do not match ordered owner approval")
		}
	}
	review.Binary, review.Assets = binary, assets
	if err := validateCompatibilityReview(review); err != nil {
		return compatibilityReview{}, err
	}
	return review, nil
}
