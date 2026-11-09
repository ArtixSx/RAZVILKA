//go:build linux

package updatecheck

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// This private per-call reader keeps every original process/FD/birth/argv
// read from fileProcessOf and bootstrapControllerAt. Ordinary and bootstrap
// role callers each supply their own original expected helper digest. Only
// repeated SHA over identical fully reread bytes is replaced; generic process
// and command readers remain unchanged.
func (r *ordinaryExecutableImage) processAt(pid int) (fileProcess, error) {
	var process fileProcess
	if err := r.current(); err != nil {
		return process, err
	}
	if pid <= 1 {
		return process, ErrFileProtocol
	}
	boot, err := fileBoot()
	if err != nil {
		return process, err
	}
	start, _, err := fileBirth(pid)
	if err != nil {
		return process, err
	}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return process, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaximumBinaryBytes {
		return process, ErrFileProtocol
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return process, ErrFileProtocol
	}
	digest, err := r.verify(f, info.Size())
	if err != nil {
		return process, err
	}
	after, _, err := fileBirth(pid)
	if err != nil || after != start {
		return process, ErrFileProtocol
	}
	return fileProcess{Boot: boot, PID: pid, Start: start, ExecutableSHA256: digest, Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func (r *ordinaryExecutableImage) controllerAt(pid int) (bootstrapControllerFact, error) {
	var fact bootstrapControllerFact
	if err := r.current(); err != nil {
		return fact, err
	}
	process, err := r.processAt(pid)
	if err != nil {
		return fact, err
	}
	start, parent, err := fileBirth(pid)
	if err != nil || start != process.Start {
		return fact, ErrInstallerControllerRole
	}
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return fact, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 64<<10 || data[len(data)-1] != 0 {
		return fact, ErrInstallerControllerRole
	}
	defer clear(data)
	args := strings.Split(string(data[:len(data)-1]), "\x00")
	if len(args) > 256 || args[0] == "" {
		return fact, ErrInstallerControllerRole
	}
	after, err := r.processAt(pid)
	_, afterParent, birthErr := fileBirth(pid)
	if err != nil || birthErr != nil || after != process || afterParent != parent || r.original.Err() != nil {
		return fact, ErrInstallerControllerRole
	}
	return bootstrapControllerFact{process, parent, args}, nil
}
