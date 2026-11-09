//go:build !linux || !amd64 || !razvilka_native_fixture

package updatecheck

import (
	"context"
	"os/exec"
)

// Normal builds do not forward fixture descriptors/environment or inject a
// failure. Original command admission, live checks and supervision are intact.
func bindNativeModernInstaller(context.Context, *exec.Cmd, string) (func(), error) {
	return func() {}, nil
}
func bindNativeModernInit(context.Context, *SelfUpdateFileAdapter, *exec.Cmd, string, string) (func(), error) {
	return func() {}, nil
}
func nativeModernPairLiveFailure(context.Context, *SelfUpdateFileAdapter, string, bool) error {
	return nil
}
