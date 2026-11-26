//go:build linux

package components

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type packageParent struct {
	path     string
	file     *os.File
	info     os.FileInfo
	uid, gid int
}

// Package archives can carry build-runner ownership for ./opt and ./opt/etc.
// Hold only existing protected ancestors; never adopt a replacement or repair
// a foreign baseline. No package content, mode, or recursive tree is repaired.
func protectPackageParents(paths []string) ([]packageParent, error) {
	var held []packageParent
	fail := func(err error) ([]packageParent, error) {
		for _, p := range held {
			_ = p.file.Close()
		}
		return nil, fmt.Errorf("unsafe Entware package parent; installation is not verified: %w", err)
	}
	if os.Geteuid() != 0 {
		return fail(errors.New("root ownership verification requires root"))
	}
	for _, path := range paths {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fail(err)
		}
		file := os.NewFile(uintptr(fd), path)
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return fail(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		named, namedErr := os.Lstat(path)
		if !ok || namedErr != nil || !named.IsDir() || !os.SameFile(info, named) || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			_ = file.Close()
			return fail(errors.New("foreign owner or writable directory: " + path))
		}
		held = append(held, packageParent{path, file, info, int(stat.Uid), int(stat.Gid)})
	}
	return held, nil
}

func finishPackageParents(held []packageParent) (result error) {
	defer func() {
		for _, p := range held {
			result = errors.Join(result, p.file.Close())
		}
	}()
	current := func(p packageParent) error {
		named, err := os.Lstat(p.path)
		info, heldErr := p.file.Stat()
		if err != nil || heldErr != nil || !named.IsDir() || !os.SameFile(p.info, named) || !os.SameFile(p.info, info) || named.Mode() != p.info.Mode() {
			return errors.New("package changed Entware parent identity or permissions: " + p.path)
		}
		return nil
	}
	// Check every named identity before the first metadata write.
	for _, p := range held {
		if err := current(p); err != nil {
			return err
		}
	}
	for _, p := range held {
		info, err := p.file.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("package parent owner unavailable")
		}
		if int(stat.Uid) != p.uid || int(stat.Gid) != p.gid {
			if err := p.file.Chown(p.uid, p.gid); err != nil {
				return err
			}
		}
		if err := current(p); err != nil {
			return err
		}
	}
	for _, p := range held {
		if err := current(p); err != nil {
			return err
		}
		info, err := p.file.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != p.uid || int(stat.Gid) != p.gid {
			return errors.New("package parent ownership was not restored")
		}
	}
	return nil
}

func (m *Manager) withPackageParents(args []string, run func() ([]byte, error)) ([]byte, error) {
	_, native := m.Runner.(execRunner)
	if !native || m.BinDir != "/opt/bin" || len(args) == 0 || (args[0] != "install" && args[0] != "upgrade" && args[0] != "remove") {
		return run()
	}
	base, err := filepath.EvalSymlinks("/opt")
	if err != nil || base == "/" {
		return nil, errors.New("unsafe Entware package root")
	}
	held, err := protectPackageParents([]string{base, filepath.Join(base, "etc")})
	if err != nil {
		return nil, err
	}
	out, runErr := run()
	closingBase, baseErr := os.Stat("/opt")
	if baseErr != nil || !os.SameFile(held[0].info, closingBase) {
		for _, p := range held {
			_ = p.file.Close()
		}
		return out, errors.Join(runErr, errors.New("Entware root changed during package operation; installation is not verified"))
	}
	if err := finishPackageParents(held); err != nil {
		return out, errors.Join(runErr, fmt.Errorf("Entware parent protection failed; installation is not verified: %w", err))
	}
	return out, runErr
}
