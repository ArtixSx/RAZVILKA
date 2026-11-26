//go:build linux

package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

type mihomoProbeOriginLinux struct {
	self                    *mihomoProbeOriginLinux
	origin                  MihomoProbeParentOrigin
	executable, pidns, proc *os.File
	exeInfo                 os.FileInfo
}

func originStat(info os.FileInfo) (uint64, uint64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrMihomoProbeOrigin
	}
	return uint64(s.Dev), s.Ino, nil
}
func originFileStat(file *os.File) (uint64, uint64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, 0, err
	}
	return originStat(info)
}

func originBoot() (string, error) {
	raw, err := originProcRead("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return "", ErrMihomoProbeOrigin
	}
	boot := strings.TrimSpace(string(raw))
	if !netidentity.ValidBootID(boot) {
		return "", ErrMihomoProbeOrigin
	}
	return boot, nil
}
func originBirth(path string, pid int) (uint64, error) {
	raw, err := originProcRead(path, 16<<10)
	if err != nil {
		return 0, err
	}
	if len(raw) > 16<<10 {
		return 0, ErrMihomoProbeOrigin
	}
	end := strings.LastIndexByte(string(raw), ')')
	first := strings.IndexByte(string(raw), ' ')
	if end < 0 || first < 0 || string(raw[:first]) != strconv.Itoa(pid) {
		return 0, ErrMihomoProbeOrigin
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, ErrMihomoProbeOrigin
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func originProcRead(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrMihomoProbeOrigin
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrMihomoProbeOrigin
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrMihomoProbeOrigin
	}
	after, err := file.Stat()
	named, namedErr := os.Stat(path)
	if err != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Mode() != after.Mode() || before.Mode() != named.Mode() {
		return nil, ErrMihomoProbeOrigin
	}
	return raw, nil
}

func originProcCurrent(proc, pidns *os.File, o MihomoProbeParentOrigin) error {
	var fs unix.Statfs_t
	if proc == nil || pidns == nil || unix.Fstatfs(int(proc.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return ErrMihomoProbeOrigin
	}
	dev, ino, err := originFileStat(proc)
	if err != nil || dev != o.ProcDevice || ino != o.ProcInode {
		return ErrMihomoProbeOrigin
	}
	dev, ino, err = originFileStat(pidns)
	if err != nil || dev != o.PIDNamespaceDevice || ino != o.PIDNamespaceInode {
		return ErrMihomoProbeOrigin
	}
	for _, p := range []struct {
		path     string
		dev, ino uint64
	}{{"/proc", o.ProcDevice, o.ProcInode}, {"/proc/self/ns/pid", o.PIDNamespaceDevice, o.PIDNamespaceInode}} {
		info, err := os.Stat(p.path)
		if err != nil {
			return ErrMihomoProbeOrigin
		}
		d, i, e := originStat(info)
		if e != nil || d != p.dev || i != p.ino {
			return ErrMihomoProbeOrigin
		}
	}
	self, err := os.Readlink("/proc/self")
	if err != nil || self != strconv.Itoa(os.Getpid()) {
		return ErrMihomoProbeOrigin
	}
	return nil
}

func originHash(ctx context.Context, file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128<<20 {
		return "", ErrMihomoProbeOrigin
	}
	h := sha256.New()
	buf := make([]byte, 256<<10)
	for off := int64(0); off < info.Size(); {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		want := int(min(int64(len(buf)), info.Size()-off))
		n, e := file.ReadAt(buf[:want], off)
		if n != want || e != nil {
			return "", ErrMihomoProbeOrigin
		}
		h.Write(buf[:n])
		off += int64(n)
	}
	var tail [1]byte
	if n, e := file.ReadAt(tail[:], info.Size()); n != 0 || !errors.Is(e, io.EOF) {
		return "", ErrMihomoProbeOrigin
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return "", ErrMihomoProbeOrigin
	}
	return hex.EncodeToString(h.Sum(nil)), ctx.Err()
}

func captureMihomoProbeOrigin(ctx context.Context) (owner mihomoProbeOriginOwner, result error) {
	if ctx == nil {
		return nil, ErrMihomoProbeOrigin
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o := &mihomoProbeOriginLinux{origin: MihomoProbeParentOrigin{Schema: 1, PID: os.Getpid(), DeathSignal: "linux-pdeathsig-sigkill-v1"}}
	o.self = o
	defer func() {
		if result != nil {
			result = errors.Join(result, o.close())
		}
	}()
	var err error
	o.proc, err = os.Open("/proc")
	if err != nil {
		return nil, err
	}
	o.pidns, err = os.Open("/proc/self/ns/pid")
	if err != nil {
		return nil, err
	}
	o.executable, err = os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	o.origin.ProcDevice, o.origin.ProcInode, err = originFileStat(o.proc)
	if err != nil {
		return nil, err
	}
	o.origin.PIDNamespaceDevice, o.origin.PIDNamespaceInode, err = originFileStat(o.pidns)
	if err != nil {
		return nil, err
	}
	o.exeInfo, err = o.executable.Stat()
	if err != nil {
		return nil, err
	}
	o.origin.ExecutableSize = o.exeInfo.Size()
	o.origin.ExecutableDevice, o.origin.ExecutableInode, err = originStat(o.exeInfo)
	if err != nil {
		return nil, err
	}
	o.origin.BootID, err = originBoot()
	if err != nil {
		return nil, err
	}
	o.origin.StartTicks, err = originBirth("/proc/self/stat", o.origin.PID)
	if err != nil {
		return nil, err
	}
	o.origin.ExecutableSHA256, err = originHash(ctx, o.executable)
	if err != nil {
		return nil, err
	}
	if err := o.current(ctx); err != nil {
		return nil, err
	}
	return o, nil
}
func (o *mihomoProbeOriginLinux) reference() MihomoProbeParentOrigin { return o.origin }
func (o *mihomoProbeOriginLinux) current(ctx context.Context) error {
	if ctx == nil {
		return ErrMihomoProbeOrigin
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o == nil || o.self != o || o.executable == nil || o.origin.Validate() != nil || o.origin.PID != os.Getpid() {
		return ErrMihomoProbeOrigin
	}
	if err := originProcCurrent(o.proc, o.pidns, o.origin); err != nil {
		return err
	}
	boot, err := originBoot()
	if err != nil || boot != o.origin.BootID {
		return ErrMihomoProbeOrigin
	}
	check := func() error {
		start, err := originBirth("/proc/self/stat", o.origin.PID)
		if err != nil || start != o.origin.StartTicks {
			return ErrMihomoProbeOrigin
		}
		named, err := os.Stat("/proc/self/exe")
		if err != nil || !os.SameFile(named, o.exeInfo) || named.Mode() != o.exeInfo.Mode() {
			return ErrMihomoProbeOrigin
		}
		return originProcCurrent(o.proc, o.pidns, o.origin)
	}
	if err := check(); err != nil {
		return err
	}
	hash, err := originHash(ctx, o.executable)
	if err != nil || hash != o.origin.ExecutableSHA256 {
		return errors.Join(err, ErrMihomoProbeOrigin)
	}
	return errors.Join(check(), ctx.Err())
}
func (o *mihomoProbeOriginLinux) close() error {
	var result error
	for _, f := range []*os.File{o.executable, o.pidns, o.proc} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	o.executable, o.pidns, o.proc = nil, nil, nil
	return result
}

// Absence comparison only: an image change at the same PID/start still means
// the original process is alive. A different PID namespace always refuses.
func ObserveMihomoProbeParentGone(ctx context.Context, o MihomoProbeParentOrigin) error {
	if ctx == nil {
		return ErrMihomoProbeOrigin
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.Validate() != nil {
		return ErrMihomoProbeOrigin
	}
	proc, err := os.Open("/proc")
	if err != nil {
		return err
	}
	defer proc.Close()
	pidns, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		return err
	}
	defer pidns.Close()
	if err := originProcCurrent(proc, pidns, o); err != nil {
		return err
	}
	boot, err := originBoot()
	if err != nil || boot != o.BootID {
		return ErrMihomoProbeOrigin
	}
	for range 2 {
		birth, err := originBirth("/proc/"+strconv.Itoa(o.PID)+"/stat", o.PID)
		if err == nil && birth == o.StartTicks {
			return ErrMihomoProbeOrigin
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrMihomoProbeOrigin
		}
		if err := originProcCurrent(proc, pidns, o); err != nil {
			return err
		}
	}
	return ctx.Err()
}
