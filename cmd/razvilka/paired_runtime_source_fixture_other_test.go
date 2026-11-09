//go:build linux && (!amd64 || !razvilka_native_fixture)

package main

import (
	"os/exec"
	"testing"
)

func nativePairedRuntimeSource(testing.TB, *exec.Cmd) func() { return func() {} }
