//go:build linux && razvilka_native_fixture

package usquediag

import "context"

// ProbeOwnedNetworkNativeFixture lets the isolated dataplane fixture exercise
// the real target and network leaf behind its local original child. Real USQUE
// executable and underlay identity are tested independently of this fixture.
func ProbeOwnedNetworkNativeFixture(ctx context.Context, request OwnedNetworkRequest) error {
	_, err := probeOwnedNetwork(ctx, request)
	return err
}
