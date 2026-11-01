package components

// MihomoRuntimeImage is comparison data for recognizing a running copy of a
// reviewed executable. It grants no install, process, cleanup or source owner.
type MihomoRuntimeImage struct {
	SHA256 string
	Size   int64
}

// ReviewedMihomoRuntimeImages includes every executable this controller can
// start, irrespective of the mutable component manager's selected platform.
func ReviewedMihomoRuntimeImages() []MihomoRuntimeImage {
	images := make([]MihomoRuntimeImage, 0, 2)
	for _, arch := range []string{"amd64", "arm64"} {
		ref, err := mihomoReviewedRawArtifact(arch)
		if err != nil {
			return nil
		}
		images = append(images, MihomoRuntimeImage{SHA256: ref.SHA256, Size: ref.Size})
	}
	return images
}
