package components

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const singBoxInitName = "S99sing-box"
const maxPackageInitBytes = 16 << 10

// This is the reviewed Entware sing-box-go init template, not a shell parser.
// Unknown commands, overrides or alternative startup scripts require manual
// ownership review. We never execute a package init merely to inspect it.
var singBoxInitLines = []string{
	"PROCS=sing-box",
	`ARGS="run -D /opt/var/lib/$PROCS -C /opt/etc/$PROCS"`,
	`PREARGS=""`,
	"DESC=$PROCS",
	"PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	". /opt/etc/init.d/rc.func",
}

type singBoxInitGuard struct {
	root *os.Root
	path string
	info os.FileInfo
}

func (m *Manager) prepareSingBoxInit(installed bool) (*singBoxInitGuard, error) {
	path := defaultValue(m.InitDir, "/opt/etc/init.d")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("init directory must be an absolute clean path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("init directory is missing or is not a regular directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	g := &singBoxInitGuard{root: root, path: path, info: info}
	if err := g.checkDirectory(); err != nil {
		root.Close()
		return nil, err
	}
	data, _, exists, err := g.read()
	if err == nil && exists && !installed {
		err = errors.New("Sing-box init exists without an installed package; ownership is unknown")
	}
	if err == nil && exists {
		_, err = disabledSingBoxInit(data)
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return g, nil
}

func (g *singBoxInitGuard) checkDirectory() error {
	current, err := os.Lstat(g.path)
	if err != nil || !current.IsDir() || !os.SameFile(current, g.info) {
		return errors.New("init directory was replaced")
	}
	opened, err := g.root.Stat(".")
	if err != nil || !os.SameFile(opened, g.info) {
		return errors.New("init directory identity changed")
	}
	if _, err := g.root.Lstat("S51sing-box"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("alternative Sing-box startup script requires ownership review")
	}
	return nil
}

func (g *singBoxInitGuard) read() ([]byte, os.FileInfo, bool, error) {
	if err := g.checkDirectory(); err != nil {
		return nil, nil, false, err
	}
	before, err := g.root.Lstat(singBoxInitName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxPackageInitBytes {
		return nil, nil, true, errors.New("package init must be a bounded regular file")
	}
	f, err := g.root.Open(singBoxInitName)
	if err != nil {
		return nil, nil, true, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return nil, nil, true, errors.New("package init was replaced")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPackageInitBytes+1))
	if err != nil || len(data) > maxPackageInitBytes {
		return nil, nil, true, errors.New("package init could not be read within its size limit")
	}
	return data, actual, true, nil
}

func (g *singBoxInitGuard) temporary() (*os.File, string, error) {
	name := ".razvilka-sing-box-init-" + rand.Text()
	f, err := g.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	return f, name, err
}

func (g *singBoxInitGuard) checkWritable() error {
	f, name, err := g.temporary()
	if err != nil {
		return err
	}
	defer g.root.Remove(name)
	return f.Close()
}

func (g *singBoxInitGuard) disable(required bool) error {
	data, info, exists, err := g.read()
	if err != nil {
		return err
	}
	if !exists {
		if required {
			return errors.New("installed package has no recognized init script")
		}
		return nil // Failed before opkg unpacked this package.
	}
	disabled, err := disabledSingBoxInit(data)
	if err != nil {
		return err
	}
	if bytes.Equal(data, disabled) {
		return nil
	}
	f, name, err := g.temporary()
	if err != nil {
		return err
	}
	defer g.root.Remove(name)
	defer f.Close()
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := f.Write(disabled); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	current, currentInfo, exists, err := g.read()
	if err != nil || !exists || !os.SameFile(info, currentInfo) || !bytes.Equal(current, data) {
		return errors.New("package init changed before disabling")
	}
	if err := g.root.Rename(name, singBoxInitName); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		dir, err := g.root.Open(".")
		if err != nil {
			return err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return err
		}
	}
	actual, _, exists, err := g.read()
	if err != nil || !exists || !bytes.Equal(actual, disabled) {
		return errors.New("disabled package init could not be verified")
	}
	return nil
}

func disabledSingBoxInit(data []byte) ([]byte, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("unknown Sing-box init template")
	}
	lines := strings.Split(string(data), "\n")
	next, enabledLine := 0, -1
	for index, line := range lines {
		line = strings.TrimSpace(line)
		if index == 0 {
			if line != "#!/bin/sh" {
				return nil, errors.New("unknown Sing-box init interpreter")
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if enabledLine == -1 && next == 0 && (line == "ENABLED=yes" || line == "ENABLED=no") {
			enabledLine = index
			continue
		}
		if enabledLine == -1 || next >= len(singBoxInitLines) || line != singBoxInitLines[next] {
			return nil, errors.New("custom Sing-box init requires ownership review")
		}
		next++
	}
	if enabledLine == -1 || next != len(singBoxInitLines) {
		return nil, errors.New("incomplete Sing-box init template")
	}
	lines[enabledLine] = strings.Replace(lines[enabledLine], "ENABLED=yes", "ENABLED=no", 1)
	return []byte(strings.Join(lines, "\n")), nil
}
