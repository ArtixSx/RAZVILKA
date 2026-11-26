package usquediag

import (
	"errors"
	"net/netip"
)

// ValidateOwnedUSQUENativeAssets shares the producer's audited executable and
// strict existing-session ABI. It neither reads files nor issues admission.
// architecture is the native runner's GOARCH, never an account/CLI assertion.
func ValidateOwnedUSQUENativeAssets(session []byte, transport, binarySHA256, architecture string) (netip.AddrPort, error) {
	if !OwnedUSQUENativeBinaryAudited(binarySHA256, architecture) {
		return netip.AddrPort{}, errors.New("native-usque-binary-not-audited")
	}
	endpoint, err := SelectedOwnedUSQUEEndpoint(session, transport)
	if err != nil || !ownedConfigPin(session, OwnedRuntimeRequest{Transport: transport, Endpoint: endpoint}) {
		return netip.AddrPort{}, errors.New("native-usque-account-invalid")
	}
	return endpoint, nil
}

// OwnedUSQUENativeBinaryAudited is a pure executable/architecture allowlist
// check. It grants no execution authority and does not inspect private input.
func OwnedUSQUENativeBinaryAudited(binarySHA256, architecture string) bool {
	return architecture != "" && ownedUSQUE421[binarySHA256] == architecture
}
