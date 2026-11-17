//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Only the original lab source coordinates pass to the actual public CLI.
// The real child rechecks the profile, outer namespace and all native sources.
func nativePairedRuntimeSource(t testing.TB, cmd *exec.Cmd) func() {
	t.Helper()
	review, root := os.Getenv("RAZVILKA_RUNTIME_NATIVE_REVIEW"), os.Getenv("TMPDIR")
	if review == "" {
		return func() {}
	}
	if cmd == nil || len(cmd.ExtraFiles) != 0 || len(cmd.Args) < 2 || (cmd.Args[1] != "self-update-bootstrap-old193" && cmd.Args[1] != "self-update-paired-restore") || !filepath.IsAbs(root) || review != filepath.Join(root, "runtime-native-tool-review.json") || os.Getenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD") != "3" {
		t.Fatal("unexpected native public CLI source coordinates")
	}
	fd, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal("original outer namespace not retained", err)
	}
	file := os.NewFile(uintptr(fd), "original native outer namespace")
	var once sync.Once
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/opt/root", "LANG=C", "LC_ALL=C",
		"TMPDIR=" + root, "RAZVILKA_RUNTIME_NATIVE_REVIEW=" + review, "RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3"}
	return func() { once.Do(func() { _ = file.Close() }) }
}
