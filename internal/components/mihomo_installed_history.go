package components

// Read-only recognition of a reviewed predecessor is not a release selector.
// All production installation and validation targets remain 1.19.33.
func mihomoInstalledRawArtifact(version, arch string) (mihomoArtifactReference, error) {
	if version == ReviewedMihomoVersion {
		return mihomoReviewedRawArtifact(arch)
	}
	if version == "1.19.32" && arch == "amd64" {
		return mihomoArtifactReference{SHA256: "3122d100e8177501776109f1a6253a694611627cf4d7c7ec82705855cf8626a8", Size: 61993086}, nil
	}
	return mihomoArtifactReference{}, ErrRecoveryAuthority
}
