package netidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type buildTuple struct {
	Manufacturer, Model, Device, Release, Sandbox, Title, Arch, NDM, FirmwareVersion string
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
		Build:        buildTuple{"Netcraze Ltd.", "Ultra (NC-1812)", "Ultra", "5.01.C.6.0-1", "stable", "5.1.6", "aarch64", "exact: 0-996b1e0", "5.1.C.6.0"},
	}
}
func (p reviewedProfile) hash() string {
	raw, _ := json.Marshal(p)
	h := sha256.Sum256(append([]byte("razvilka-network-platform-review-v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}

// Parse only unique exact version fields from bounded NDMC text. Other
// informational lines cannot supply or override any identity field.
func parseBuild(raw []byte) (buildTuple, error) {
	var v buildTuple
	if len(raw) == 0 || len(raw) > 8192 {
		return v, ErrUnknown
	}
	for _, b := range raw {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' || b > 126 {
			return v, ErrUnknown
		}
	}
	fields := map[string]*string{"manufacturer": &v.Manufacturer, "model": &v.Model, "device": &v.Device, "release": &v.Release, "sandbox": &v.Sandbox, "title": &v.Title, "arch": &v.Arch, "ndm": &v.NDM, "version": &v.FirmwareVersion}
	seen := map[string]bool{}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 128 {
		return buildTuple{}, ErrUnknown
	}
	for _, line := range lines {
		if len(line) > 1024 {
			return buildTuple{}, ErrUnknown
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		field, wanted := fields[key]
		if !wanted {
			continue
		}
		value = strings.TrimSpace(value)
		if seen[key] || value == "" || len(value) > 128 {
			return buildTuple{}, ErrUnknown
		}
		seen[key] = true
		*field = value
	}
	if len(seen) != len(fields) {
		return buildTuple{}, ErrUnknown
	}
	return v, nil
}
