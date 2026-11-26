//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func nativeOperatorPlatform() error {
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		return errRefused
	}
	return nil
}
func ownerOK(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0
}
func readOnlyFileFlags() int { return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK }

func checkOperatorPaths(p paths) error {
	for _, path := range []string{p.installation, p.configDir, p.state, p.executable, p.init, p.pid, p.proc} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errRefused
		}
	}
	for _, path := range []string{p.installation, p.configDir, p.state, filepath.Dir(p.executable), filepath.Dir(p.init), filepath.Dir(p.pid)} {
		rel, err := filepath.Rel(p.installation, path)
		if err != nil || rel != "." && !filepath.IsLocal(rel) {
			return errRefused
		}
		for current := path; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownerOK(info) {
				return errRefused
			}
			if current == p.installation {
				break
			}
		}
	}
	return nil
}

// The four original private lifetime locks exclude cooperating daemons.
// This bounded additional process/pidfile observation also refuses an older
// panel or recovery process which has not acquired those locks. It grants no
// permission to stop a process and never executes a native command.
func panelAbsent(ctx context.Context, p paths) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r, err := ownedfs.Open(p.installation)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(p.installation, p.pid)
	if err != nil {
		_ = r.Close()
		return err
	}
	_, statErr := r.Stat(rel)
	closeErr := r.Close()
	if !errors.Is(statErr, os.ErrNotExist) || closeErr != nil {
		return errRefused
	}
	dir, err := os.Open(p.proc)
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(8193)
	closeErr = dir.Close()
	if err != nil && err != io.EOF || closeErr != nil || len(entries) > 8192 {
		return errRefused
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if !entry.IsDir() {
			return errRefused
		}
		base := filepath.Join(p.proc, entry.Name())
		comm, err := readProcessFile(filepath.Join(base, "comm"), 4096)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errRefused
		}
		if strings.HasPrefix(strings.TrimSpace(string(comm)), "razvilka") {
			return errRefused
		}
		args, err := readProcessFile(filepath.Join(base, "cmdline"), 128<<10)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errRefused
		}
		for _, arg := range bytes.Split(args, []byte{0}) {
			if string(arg) == p.executable {
				return errRefused
			}
		}
		executable, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errRefused
		}
		if strings.TrimSuffix(executable, " (deleted)") == p.executable {
			return errRefused
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func readProcessFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, readOnlyFileFlags(), 0)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || int64(len(b)) > limit {
		return nil, errRefused
	}
	return b, nil
}
