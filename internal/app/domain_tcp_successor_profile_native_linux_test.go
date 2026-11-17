//go:build linux && razvilka_native_fixture

package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"syscall"
	"testing"
)

const domainSuccessorProfileLimit = 2 << 20

var errDomainSuccessorProfileBound = errors.New("native successor CPU profile output bound")

type domainSuccessorProfileWriter struct {
	file    *os.File
	bytes   int64
	failure error
}

func (w *domainSuccessorProfileWriter) Write(p []byte) (int, error) {
	if w.failure != nil {
		return 0, w.failure
	}
	if int64(len(p)) > domainSuccessorProfileLimit-w.bytes {
		w.failure = errDomainSuccessorProfileBound
		return 0, w.failure
	}
	n, err := w.file.Write(p)
	w.bytes += int64(n)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	w.failure = err
	return n, err
}

type domainSuccessorCPUProfile struct {
	dir      *os.File
	path     string
	info     os.FileInfo
	writer   *domainSuccessorProfileWriter
	fileInfo os.FileInfo
	stopped  bool
}

func domainSuccessorProfileDirectory(path string) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, errors.New("successor profile canonical directory required")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, nil, errors.New("successor profile symlink directory refused")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	uid := uint64(os.Geteuid())
	if ok && uint64(st.Uid) != uid {
		original, parseErr := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
		if parseErr != nil || original == 0 || uint64(st.Uid) != original {
			return nil, nil, errors.New("successor profile owner mismatch")
		}
	}
	if !ok || !info.IsDir() || (info.Mode().Perm() != 0700 && info.Mode().Perm() != 0755) || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, nil, errors.New("successor profile directory mode")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	held, err := dir.Stat()
	if err != nil || !domainSuccessorProfileSameDirectory(info, held) {
		_ = dir.Close()
		return nil, nil, errors.New("successor profile directory changed")
	}
	return dir, info, nil
}
func domainSuccessorProfileSameDirectory(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.IsDir() || !b.IsDir() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && os.SameFile(a, b) && a.Mode() == b.Mode() && x.Uid == y.Uid && x.Gid == y.Gid
}

func startDomainSuccessorCPUProfile() (*domainSuccessorCPUProfile, error) {
	output := os.Getenv("RAZVILKA_DOMAIN_PROFILE_OUTPUT")
	if output == "" {
		return nil, nil
	}
	dir, info, err := domainSuccessorProfileDirectory(output)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = dir.Close()
		}
	}()
	// The original already-existing output directory is retained. No file with
	// this fixed name may be replaced, followed, reopened or silently adopted.
	fd, err := syscall.Openat(int(dir.Fd()), "successor-run.cpu.pprof", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "successor-run.cpu.pprof")
	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	profile := &domainSuccessorCPUProfile{dir: dir, path: output, info: info, writer: &domainSuccessorProfileWriter{file: file}, fileInfo: fi}
	if err := profile.current(); err != nil {
		_ = file.Close()
		return nil, err
	}
	// The Go runtime refuses a concurrent GEN1 profiler; never stop/reuse it.
	if err := pprof.StartCPUProfile(profile.writer); err != nil {
		_ = file.Close()
		return nil, err
	}
	keep = true
	return profile, nil
}
func (p *domainSuccessorCPUProfile) current() error {
	if p == nil {
		return nil
	}
	canonical, canonicalErr := filepath.EvalSymlinks(p.path)
	if canonicalErr != nil || canonical != p.path {
		return errors.New("successor profile directory resolution changed")
	}
	named, err := os.Lstat(p.path)
	held, heldErr := p.dir.Stat()
	if err != nil || heldErr != nil || !domainSuccessorProfileSameDirectory(p.info, named) || !domainSuccessorProfileSameDirectory(p.info, held) {
		return errors.New("successor profile retained directory changed")
	}
	current, err := p.writer.file.Stat()
	name, nameErr := os.Lstat(filepath.Join(p.path, "successor-run.cpu.pprof"))
	if err != nil || nameErr != nil || !os.SameFile(p.fileInfo, current) || !os.SameFile(current, name) || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 || name.Mode() != current.Mode() || name.Size() > domainSuccessorProfileLimit || current.Size() > domainSuccessorProfileLimit {
		return errors.New("successor profile retained file changed")
	}
	st, ok := current.Sys().(*syscall.Stat_t)
	namedStat, namedOK := name.Sys().(*syscall.Stat_t)
	originalStat, originalOK := p.fileInfo.Sys().(*syscall.Stat_t)
	if !ok || !namedOK || !originalOK || st.Uid != originalStat.Uid || st.Gid != originalStat.Gid || namedStat.Uid != st.Uid || namedStat.Gid != st.Gid || st.Uid != uint32(os.Geteuid()) {
		return errors.New("successor profile retained file owner")
	}
	return nil
}
func (p *domainSuccessorCPUProfile) finish(t *testing.T, joined bool) error {
	if p == nil {
		return nil
	}
	if p.stopped {
		return errors.New("successor profile already stopped")
	}
	p.stopped = true
	// Stop joins the runtime's asynchronous profile writer. Its Write error is
	// retained separately, because StopCPUProfile has no error return value.
	pprof.StopCPUProfile()
	err := errors.Join(p.writer.failure, p.current(), p.writer.file.Sync())
	err = errors.Join(err, p.writer.file.Close(), p.dir.Close())
	t.Logf("GEN2_CPU_PROFILE_COMPLETE bytes=%d joined=%t overflow=%t output_error=%t; successor preparation + Run through join attempt, profiling overhead included, not readiness or cleanup proof", p.writer.bytes, joined, errors.Is(p.writer.failure, errDomainSuccessorProfileBound), err != nil)
	return err
}

func TestDomainSuccessorCPUProfileWriterBound(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := &domainSuccessorProfileWriter{file: f}
	block := make([]byte, 32<<10)
	for range domainSuccessorProfileLimit / len(block) {
		if n, err := w.Write(block); err != nil || n != len(block) {
			t.Fatal(n, err)
		}
	}
	if n, err := w.Write([]byte{1}); n != 0 || !errors.Is(err, errDomainSuccessorProfileBound) {
		t.Fatal("overflow not retained", n, err)
	}
	info, err := f.Stat()
	if err != nil || info.Size() != domainSuccessorProfileLimit {
		t.Fatal("bound", info, err)
	}
	if _, err := w.Write(nil); !errors.Is(err, errDomainSuccessorProfileBound) {
		t.Fatal("overflow forgotten")
	}
}
func TestDomainSuccessorCPUProfileOwnershipAndExclusiveName(t *testing.T) {
	output := t.TempDir()
	t.Setenv("RAZVILKA_DOMAIN_PROFILE_OUTPUT", output)
	if err := os.WriteFile(filepath.Join(output, "successor-run.cpu.pprof"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if p, err := startDomainSuccessorCPUProfile(); err == nil || p != nil {
		t.Fatal("existing profile adopted")
	}
	raw, err := os.ReadFile(filepath.Join(output, "successor-run.cpu.pprof"))
	if err != nil || string(raw) != "original" {
		t.Fatal("existing bytes changed", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(output, link); err != nil {
		t.Fatal(err)
	}
	if d, _, err := domainSuccessorProfileDirectory(link); err == nil {
		d.Close()
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(output, 0777); err != nil {
		t.Fatal(err)
	}
	if d, _, err := domainSuccessorProfileDirectory(output); err == nil {
		d.Close()
		t.Fatal("writable directory accepted")
	}
}
func TestDomainSuccessorCPUProfileActualCompletionAndNoOverlap(t *testing.T) {
	output := t.TempDir()
	t.Setenv("RAZVILKA_DOMAIN_PROFILE_OUTPUT", output)
	p, err := startDomainSuccessorCPUProfile()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !p.stopped {
			_ = p.finish(t, false)
		}
	})
	// Actual Go profiler ownership refuses another Start; no replacement of the
	// current GEN1/GEN2 profiler is performed by this native helper.
	other := t.TempDir()
	t.Setenv("RAZVILKA_DOMAIN_PROFILE_OUTPUT", other)
	if second, err := startDomainSuccessorCPUProfile(); err == nil || second != nil {
		t.Fatal("concurrent profiler accepted")
	}
	if err := p.finish(t, true); err != nil {
		t.Fatal(err)
	}
	if p.writer.bytes <= 0 {
		t.Fatal("actual CPU stream missing")
	}
	if err := p.finish(t, true); err == nil {
		t.Fatal("duplicate stop accepted")
	}
}
func TestDomainSuccessorCPUProfileRetainedDirectoryReplacement(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "output")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAZVILKA_DOMAIN_PROFILE_OUTPUT", output)
	p, err := startDomainSuccessorCPUProfile()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !p.stopped {
			_ = p.finish(t, false)
		}
	})
	if err := os.Rename(output, output+"-old"); err != nil {
		_ = p.finish(t, false)
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		_ = p.finish(t, false)
		t.Fatal(err)
	}
	if err := p.finish(t, false); err == nil {
		t.Fatal("replacement accepted")
	}
	if _, err := os.Lstat(filepath.Join(output, "successor-run.cpu.pprof")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement directory adopted")
	}
}

func TestDomainSuccessorCPUProfileWriterFailureRetained(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	w := &domainSuccessorProfileWriter{file: f}
	if _, err := w.Write([]byte{1}); err == nil || w.failure == nil {
		t.Fatal("write failure lost")
	}
	first := w.failure
	if _, err := w.Write(nil); err != first {
		t.Fatal("write failure not retained")
	}
}
