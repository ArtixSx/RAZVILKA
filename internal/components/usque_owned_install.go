package components

import (
	"errors"

	"github.com/ArtixSx/razvilka/internal/usquediag"
)

var (
	ErrUSQUEVendorOwner        = errors.New("vendor USQUE owns the system installation")
	ErrUSQUEInstallUnsupported = errors.New("native USQUE installation unavailable on this platform or state root")
	ErrUSQUEInstallPending     = errors.New("native USQUE binary publication needs verification")
)

const reviewedUSQUERelease = "4.2.1"

// The archive digests come from the exact upstream release assets. The
// separate executable allowlist is shared with registration and live health.
var reviewedUSQUEArchives = map[string]string{
	"amd64":  "4117e20695078af9c11edecd1a826c009bbc7ea0b7f64458612b4198910bc313",
	"arm64":  "c88b061c2a567f30813d7505637d1fb6fe7ec5898b5b61fd05122409fa5ad925",
	"mips":   "6c125f6679e0549df18e69eab5208278426c00f802aa9733ac6f52b941796ec9",
	"mipsle": "2e313c8eb34d36c29d61627f16503cf293209fcfb405e8516d9c95137da3771f",
}

func reviewedUSQUEBinary(arch string, archive []byte) ([]byte, error) {
	pin := reviewedUSQUEArchives[arch]
	if pin == "" || digest(archive) != pin {
		return nil, errors.New("USQUE official archive SHA-256 mismatch or unsupported architecture")
	}
	binary, err := binaryFromZIP(archive, "usque")
	if err != nil {
		return nil, err
	}
	if !usquediag.OwnedUSQUENativeBinaryAudited(digest(binary), arch) {
		return nil, errors.New("USQUE executable SHA-256 mismatch")
	}
	return binary, nil
}
