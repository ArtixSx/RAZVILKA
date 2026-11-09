//go:build linux && amd64 && razvilka_native_fixture

package updatecheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// This fixture carries only platform-classification coordinates and the SAME
// held outer namespace through actual original command workers. It supplies no
// runtime/receipt/Stop authority. Every child constructs fresh original owners.
func bindNativeRuntimeCommand(ctx context.Context, cmd *exec.Cmd, id, command string) (func(), error) {
	noop := func() {}
	review := os.Getenv("RAZVILKA_RUNTIME_NATIVE_REVIEW")
	if review == "" && os.Getenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD") == "" {
		return noop, nil
	}
	if ctx == nil || ctx.Err() != nil || cmd == nil || os.Geteuid() != 0 || !jobIDPattern.MatchString(id) || len(cmd.ExtraFiles) != 0 ||
		cmd.Path != filepath.Join(productionUpdateRoot, id, "control.bin") || len(cmd.Args) == 0 || cmd.Args[0] != cmd.Path {
		return noop, ErrFileProtocol
	}
	switch command {
	case "stop-old-panel", "prepare-private-state", "quiesce-old-runtime":
	default:
		return noop, ErrFileProtocol
	}
	worker := len(cmd.Args) == 4 && cmd.Args[1] == "self-update-command-helper" && cmd.Args[2] == id && cmd.Args[3] == command
	child := false
	if command == "quiesce-old-runtime" && len(cmd.Args) == 5 && cmd.Args[1] == "self-update-runtime-quiesce" && cmd.Args[2] == id {
		revision, revisionErr := strconv.ParseUint(cmd.Args[3], 10, 64)
		pid, pidErr := strconv.Atoi(cmd.Args[4])
		child = revisionErr == nil && revision != 0 && strconv.FormatUint(revision, 10) == cmd.Args[3] && pidErr == nil && pid == os.Getpid() && strconv.Itoa(pid) == cmd.Args[4]
	}
	if !worker && !child {
		return noop, ErrFileProtocol
	}
	for _, value := range cmd.Env {
		key, _, _ := strings.Cut(value, "=")
		if key == "TMPDIR" || strings.HasPrefix(strings.ToUpper(key), "RAZVILKA_RUNTIME_NATIVE_") {
			return noop, ErrFileProtocol
		}
	}
	root := os.Getenv("TMPDIR")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || review != filepath.Join(root, "runtime-native-tool-review.json") || os.Getenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD") != "3" {
		return noop, ErrFileProtocol
	}
	for i, path := range []string{root, review} {
		info, err := os.Lstat(path)
		if err != nil {
			return noop, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || i == 0 && !info.IsDir() || i == 1 && (!info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096) {
			return noop, ErrFileProtocol
		}
	}
	typeID, err := unix.IoctlRetInt(3, unix.NS_GET_NSTYPE)
	var outer, current syscall.Stat_t
	if err != nil || typeID != unix.CLONE_NEWNET || syscall.Fstat(3, &outer) != nil || syscall.Stat("/proc/self/ns/net", &current) != nil || outer.Dev == current.Dev && outer.Ino == current.Ino {
		return noop, ErrFileProtocol
	}
	fd, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return noop, err
	}
	file := os.NewFile(uintptr(fd), "native original outer network namespace")
	var once sync.Once
	closeSource := func() { once.Do(func() { _ = file.Close() }) }
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = append(cmd.Env, "TMPDIR="+root, "RAZVILKA_RUNTIME_NATIVE_REVIEW="+review, "RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3")
	return closeSource, nil
}
