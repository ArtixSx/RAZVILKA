package netidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type buildTuple struct {
	// Release is the firmware release. NDW4Version is only ndw4.version,
	// and NDMExact is only ndm.exact; neither is a flattened root alias.
	Manufacturer, Model, Device, Release, Sandbox, Title, Arch, NDMExact, NDW4Version string
}
type reviewedProfile struct {
	Version                                                    int
	Semantics, KernelRelease, Machine, SDKCommit, KernelCommit string
	Build                                                      buildTuple
}

// Maintainer-accepted stock vendor ABI, not independent running-config
// attestation. There is no wildcard, environment or persisted profile catalog.
func nc1812Profile() reviewedProfile {
	return reviewedProfile{
		Version: 1, Semantics: "accepted-vendor-ABI",
		KernelRelease: "4.9-ndm-5", Machine: "aarch64",
		SDKCommit:    "1d58c10c46e270d6876836e5455fa4e9b786ad1e",
		KernelCommit: "7b6c9477d429217042117fbfa3d2e9894a087607",
		Build:        buildTuple{"Netcraze Ltd.", "Ultra (NC-1812)", "Ultra", "5.01.C.6.0-1", "stable", "5.1.6", "aarch64", "0-996b1e0", "5.1.C.6.0"},
	}
}
func (p reviewedProfile) hash() string {
	raw, _ := json.Marshal(p)
	h := sha256.Sum256(append([]byte("razvilka-network-platform-review-v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
