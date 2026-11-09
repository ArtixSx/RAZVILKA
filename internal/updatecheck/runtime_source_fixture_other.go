//go:build !linux || !amd64 || !razvilka_native_fixture

package updatecheck

import (
	"context"
	"os/exec"
)

// Production commands retain their closed environment and descriptor contract.
func bindNativeRuntimeCommand(context.Context, *exec.Cmd, string, string) (func(), error) {
	return func() {}, nil
}
