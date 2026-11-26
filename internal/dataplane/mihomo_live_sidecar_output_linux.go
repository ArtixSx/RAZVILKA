//go:build linux && !razvilka_native_fixture

package dataplane

import "io"

func mihomoLiveSidecarConfigureOutput(n *mihomoLiveSidecar) {
	n.command.Stdout, n.command.Stderr = io.Discard, io.Discard
}

func mihomoLiveSidecarFinishOutput(_ *mihomoLiveSidecar) {}
