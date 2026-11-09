//go:build !linux || !amd64 || !razvilka_native_fixture

package updatecheck

import (
	"context"
	"os/exec"
	"reflect"
	"testing"
)

func TestModernPairNormalBuildHooksAreNoOps(t *testing.T) {
	t.Setenv("RAZVILKA_MODERN_PAIR_NATIVE", "1")
	t.Setenv("RAZVILKA_RUNTIME_NATIVE_REVIEW", "/untrusted")
	cmd := exec.Command("unrelated", "argument")
	cmd.Env = []string{"UNCHANGED=1"}
	closeInstaller, err := bindNativeModernInstaller(nil, cmd, "not-an-id")
	if err != nil {
		t.Fatal(err)
	}
	closeInstaller()
	closeInit, err := bindNativeModernInit(context.Background(), nil, cmd, "not-an-id", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	closeInit()
	if err := nativeModernPairLiveFailure(nil, nil, "not-an-id", false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cmd.Env, []string{"UNCHANGED=1"}) || len(cmd.ExtraFiles) != 0 || cmd.Path != "unrelated" {
		t.Fatal("normal build fixture input changed command")
	}
}
