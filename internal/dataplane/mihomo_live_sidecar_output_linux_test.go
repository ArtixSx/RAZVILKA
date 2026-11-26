//go:build linux && !razvilka_native_fixture

package dataplane

import (
	"io"
	"os/exec"
	"testing"
)

func TestMihomoSidecarOutputNormalBuildDiscards(t *testing.T) {
	n := &mihomoLiveSidecar{command: exec.Command("unused")}
	mihomoLiveSidecarConfigureOutput(n)
	mihomoLiveSidecarFinishOutput(n)
	if n.command.Stdout != io.Discard || n.command.Stderr != io.Discard {
		t.Fatal("normal build retained sidecar output")
	}
}
