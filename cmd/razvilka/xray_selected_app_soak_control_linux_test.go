//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// This directory is independent of production control/journals. Retained
// descriptors and exact private metadata fence path replacement. ROOT only
// reads status and creates command atomically; neither file grants runtime.
type xraySelectedSoakFiles struct {
	root, control         *os.File
	rootPath, path, runID string
	rootInfo, info        os.FileInfo
	statusImage           []byte
}

func xraySelectedSoakPrivate(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && stat.Nlink == 1
}

func xraySelectedNewSoakFiles(rootPath string) (*xraySelectedSoakFiles, error) {
	fail := errors.New("private_soak_control_unavailable")
	rootFD, err := syscall.Open(rootPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	c := &xraySelectedSoakFiles{root: os.NewFile(uintptr(rootFD), "qa-soak-root"), rootPath: rootPath, path: filepath.Join(rootPath, "qa-soak-control")}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	c.rootInfo, err = c.root.Stat()
	current, pathErr := os.Lstat(rootPath)
	if err != nil || pathErr != nil || !xraySelectedSoakPrivate(c.rootInfo, true) || !os.SameFile(c.rootInfo, current) || current.Mode()&os.ModeSymlink != 0 {
		return nil, fail
	}
	if syscall.Mkdirat(rootFD, "qa-soak-control", 0700) != nil {
		return nil, fail
	}
	fd, err := syscall.Openat(rootFD, "qa-soak-control", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	c.control = os.NewFile(uintptr(fd), "qa-soak-control")
	c.info, err = c.control.Stat()
	if err != nil || c.current() != nil {
		return nil, fail
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, fail
	}
	c.runID = hex.EncodeToString(entropy[:])
	clear(entropy[:])
	ok = true
	return c, nil
}

func (c *xraySelectedSoakFiles) Close() {
	if c.control != nil {
		_ = c.control.Close()
	}
	if c.root != nil {
		_ = c.root.Close()
	}
	clear(c.statusImage)
	// Keep all private status/control/original production artifacts for ROOT.
}

func (c *xraySelectedSoakFiles) current() error {
	for _, entry := range []struct {
		file     *os.File
		original os.FileInfo
		path     string
	}{
		{c.root, c.rootInfo, c.rootPath}, {c.control, c.info, c.path},
	} {
		if entry.file == nil || entry.original == nil {
			return errors.New("soak_control_identity_changed")
		}
		held, err := entry.file.Stat()
		current, pathErr := os.Lstat(entry.path)
		if err != nil || pathErr != nil || !xraySelectedSoakPrivate(held, true) || !xraySelectedSoakPrivate(current, true) ||
			current.Mode()&os.ModeSymlink != 0 || !os.SameFile(entry.original, held) || !os.SameFile(held, current) {
			return errors.New("soak_control_identity_changed")
		}
	}
	return nil
}

func (c *xraySelectedSoakFiles) read(name string, limit int) ([]byte, error) {
	fail := errors.New("soak_control_file_unconfirmed")
	if c.current() != nil {
		return nil, fail
	}
	fd, err := syscall.Openat(int(c.control.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err == syscall.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, fail
	}
	file := os.NewFile(uintptr(fd), "qa-soak-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !xraySelectedSoakPrivate(info, false) || info.Size() < 1 || info.Size() > int64(limit) {
		return nil, fail
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	after, statErr := file.Stat()
	onPath, pathErr := os.Lstat(filepath.Join(c.path, name))
	if err != nil || len(data) != int(info.Size()) || len(data) > limit || statErr != nil || pathErr != nil || c.current() != nil ||
		!xraySelectedSoakPrivate(after, false) || !xraySelectedSoakPrivate(onPath, false) || !os.SameFile(info, after) || !os.SameFile(info, onPath) ||
		info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || onPath.Mode()&os.ModeSymlink != 0 {
		clear(data)
		return nil, fail
	}
	return data, nil
}

func (c *xraySelectedSoakFiles) Command() ([]byte, error) { return c.read("command", 128) }

func (c *xraySelectedSoakFiles) Publish(s xraySelectedSoakStatus) error {
	fail := errors.New("soak_status_unconfirmed")
	if s.RunID != c.runID || c.current() != nil {
		return fail
	}
	previous, err := c.read("status", 4096)
	defer clear(previous)
	if err != nil || !bytes.Equal(previous, c.statusImage) {
		return fail
	}
	data := s.text()
	defer clear(data)
	if len(data) > 4096 {
		return fail
	}
	fd, err := syscall.Openat(int(c.control.Fd()), ".status-next", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fail
	}
	file := os.NewFile(uintptr(fd), "qa-soak-status")
	defer file.Close()
	n, err := file.Write(data)
	if err != nil || n != len(data) || file.Sync() != nil || c.current() != nil {
		return fail
	}
	if syscall.Renameat(int(c.control.Fd()), ".status-next", int(c.control.Fd()), "status") != nil {
		return fail
	}
	clear(c.statusImage)
	c.statusImage = bytes.Clone(data)
	if c.control.Sync() != nil || c.current() != nil {
		return fail
	}
	return nil
}

// Local filesystem-only checks; never start an App, adapter, process or router
// command. ROOT can run these on Linux independently of the native opt-in.
func TestXraySelectedSoakPrivateControlFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private root-owned QA control requires root")
	}
	for _, cut := range []string{"atomic-stop", "symlink", "fifo", "hardlink", "oversized", "permissive", "directory-replaced", "status-mutated"} {
		t.Run(cut, func(t *testing.T) {
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil {
				t.Fatal("private root unavailable")
			}
			c, err := xraySelectedNewSoakFiles(root)
			if err != nil {
				t.Fatal("private control creation failed")
			}
			defer c.Close()
			s := xraySelectedSoakStatus{RunID: c.runID, Phase: "active_observed"}
			if c.Publish(s) != nil {
				t.Fatal("status publication failed")
			}
			command := filepath.Join(c.path, "command")
			switch cut {
			case "atomic-stop":
				temporary := filepath.Join(c.path, ".command-next")
				if os.WriteFile(temporary, []byte("STOP "+c.runID+"\n"), 0600) != nil || os.Rename(temporary, command) != nil {
					t.Fatal("atomic command delivery failed")
				}
			case "symlink":
				if os.Symlink(filepath.Join(c.path, "status"), command) != nil {
					t.Fatal("symlink fixture failed")
				}
			case "fifo":
				if syscall.Mkfifo(command, 0600) != nil {
					t.Fatal("fifo fixture failed")
				}
			case "hardlink":
				if os.Link(filepath.Join(c.path, "status"), command) != nil {
					t.Fatal("hardlink fixture failed")
				}
			case "oversized":
				if os.WriteFile(command, bytes.Repeat([]byte("x"), 129), 0600) != nil {
					t.Fatal("oversized fixture failed")
				}
			case "permissive":
				if os.WriteFile(command, []byte("STOP "+c.runID), 0600) != nil || os.Chmod(command, 0644) != nil {
					t.Fatal("permission fixture failed")
				}
			case "directory-replaced":
				if os.Rename(c.path, c.path+"-retained") != nil || os.Mkdir(c.path, 0700) != nil {
					t.Fatal("replacement fixture failed")
				}
			case "status-mutated":
				if os.WriteFile(filepath.Join(c.path, "status"), []byte("runtime_grant=fake\n"), 0600) != nil {
					t.Fatal("mutation fixture failed")
				}
				if c.Publish(s) == nil {
					t.Fatal("changed coordination status was overwritten")
				}
				return
			}
			data, err := c.Command()
			defer clear(data)
			if cut == "atomic-stop" {
				verb, parseErr := xraySelectedSoakCommand(data, c.runID)
				if err != nil || parseErr != nil || verb != "STOP" {
					t.Fatal("real atomic command was rejected")
				}
			} else if err == nil {
				t.Fatal("unsafe control file became an accepted command")
			}
		})
	}
}
