//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"syscall"
	"testing"
)

const domainOriginalAllocsLimit = 64 << 20
const domainOriginalAllocsName = "original-run.allocs.pprof"

var errDomainOriginalAllocsBound = errors.New("native allocation profile output bound")

type domainOriginalAllocsWriter struct {
	writer io.Writer
	limit  int64
	bytes  int64
	err    error
}

func (w *domainOriginalAllocsWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(data)) > w.limit-w.bytes {
		w.err = errDomainOriginalAllocsBound
		return 0, w.err
	}
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

// Invoked only after the original Run joined and its CPU writer stopped.
// The runtime's existing sampled allocation history is written verbatim; no GC,
// sampling-rate change, object payload capture or interval-reset is requested.
func writeDomainOriginalAllocsProfile(work string, expected os.FileInfo) (int64, error) {
	return writeDomainOriginalAllocsWith(work, expected, func(w io.Writer) error {
		profile := pprof.Lookup("allocs")
		if profile == nil || runtime.MemProfileRate <= 0 {
			return errors.New("allocation sampling unavailable")
		}
		return profile.WriteTo(w, 0)
	})
}

func writeDomainOriginalAllocsWith(work string, expected os.FileInfo, write func(io.Writer) error) (count int64, result error) {
	if write == nil || expected == nil || expected.Mode().Perm() != 0700 {
		return 0, errors.New("allocation profile requires original private directory")
	}
	dir, info, err := domainSuccessorProfileDirectory(work)
	if err != nil {
		return 0, err
	}
	defer func() { result = errors.Join(result, dir.Close()) }()
	if !domainSuccessorProfileSameDirectory(expected, info) {
		return 0, errors.New("allocation profile original directory changed")
	}
	fd, err := syscall.Openat(int(dir.Fd()), domainOriginalAllocsName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), domainOriginalAllocsName)
	defer func() { result = errors.Join(result, file.Close()) }()
	initial, err := file.Stat()
	if err != nil {
		return 0, err
	}
	initialStat, initialOK := initial.Sys().(*syscall.Stat_t)
	if !initialOK {
		return 0, errors.New("allocation profile original file metadata unavailable")
	}
	current := func() error {
		canonical, canonicalErr := filepath.EvalSymlinks(work)
		namedDir, namedErr := os.Lstat(work)
		heldDir, heldErr := dir.Stat()
		if canonicalErr != nil || canonical != work || namedErr != nil || heldErr != nil || !domainSuccessorProfileSameDirectory(expected, namedDir) || !domainSuccessorProfileSameDirectory(expected, heldDir) {
			return errors.New("allocation profile directory custody changed")
		}
		held, heldErr := file.Stat()
		named, namedErr := os.Lstat(filepath.Join(work, domainOriginalAllocsName))
		if heldErr != nil || namedErr != nil || !held.Mode().IsRegular() || held.Mode().Perm() != 0600 || held.Mode() != named.Mode() || !os.SameFile(initial, held) || !os.SameFile(held, named) || held.Size() != count || held.Size() > domainOriginalAllocsLimit {
			return errors.New("allocation profile retained file changed")
		}
		hs, hok := held.Sys().(*syscall.Stat_t)
		ns, nok := named.Sys().(*syscall.Stat_t)
		if !hok || !nok || hs.Uid != uint32(os.Geteuid()) || hs.Uid != initialStat.Uid || hs.Gid != initialStat.Gid || ns.Uid != hs.Uid || ns.Gid != hs.Gid || hs.Nlink != 1 || ns.Nlink != 1 {
			return errors.New("allocation profile owner changed")
		}
		return nil
	}
	if err := current(); err != nil {
		return 0, err
	}
	writer := &domainOriginalAllocsWriter{writer: file, limit: domainOriginalAllocsLimit}
	writeErr := write(writer)
	count = writer.bytes
	return count, errors.Join(writeErr, writer.err, file.Sync(), current())
}

func TestDomainOriginalAllocsProfileWriter(t *testing.T) {
	var buffer bytes.Buffer
	w := &domainOriginalAllocsWriter{writer: &buffer, limit: 4}
	if n, err := w.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := w.Write([]byte("5")); n != 0 || !errors.Is(err, errDomainOriginalAllocsBound) {
		t.Fatal(n, err)
	}
	if n, err := w.Write(nil); n != 0 || !errors.Is(err, errDomainOriginalAllocsBound) || buffer.String() != "1234" {
		t.Fatal(n, err)
	}
	short := &domainOriginalAllocsWriter{writer: domainAllocsShortWriter{}, limit: 4}
	if _, err := short.Write([]byte("1234")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short writer accepted", err)
	}
}

type domainAllocsShortWriter struct{}

func (domainAllocsShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestDomainOriginalAllocsProfileRuntimeSnapshot(t *testing.T) {
	work := t.TempDir()
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(work)
	if err != nil {
		t.Fatal(err)
	}
	rate := runtime.MemProfileRate
	count, err := writeDomainOriginalAllocsProfile(work, info)
	if err != nil || count <= 0 || runtime.MemProfileRate != rate {
		t.Fatal("profile or unchanged sampling", count, err)
	}
	data, err := os.ReadFile(filepath.Join(work, domainOriginalAllocsName))
	if err != nil || int64(len(data)) != count {
		t.Fatal(count, err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, domainOriginalAllocsLimit+1))
	if closeErr := reader.Close(); err != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > domainOriginalAllocsLimit {
		t.Fatal("incomplete binary profile", err, closeErr)
	}
}

func TestDomainOriginalAllocsProfileCustody(t *testing.T) {
	for _, kind := range []string{"full", "existing", "symlink", "directory-replaced", "file-replaced", "write-error"} {
		t.Run(kind, func(t *testing.T) {
			work := t.TempDir()
			if err := os.Chmod(work, 0700); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(work)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(work, domainOriginalAllocsName)
			called := false
			failure := errors.New("injected profile write failure")
			payload := bytes.Repeat([]byte{'x'}, (2<<20)+7)
			if kind == "existing" {
				if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				if err := os.Symlink(filepath.Join(work, "elsewhere"), name); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "directory-replaced" {
				old := work + "-old"
				if err := os.Rename(work, old); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(old) })
				if err := os.Mkdir(work, 0700); err != nil {
					t.Fatal(err)
				}
			}
			n, err := writeDomainOriginalAllocsWith(work, info, func(w io.Writer) error {
				called = true
				if kind == "write-error" {
					return failure
				}
				if _, err := w.Write(payload); err != nil {
					return err
				}
				if kind == "file-replaced" {
					if err := os.Rename(name, name+"-old"); err != nil {
						return err
					}
					return os.WriteFile(name, payload, 0600)
				}
				return nil
			})
			if kind == "full" {
				data, readErr := os.ReadFile(name)
				if err != nil || readErr != nil || n != int64(len(payload)) || !bytes.Equal(data, payload) {
					t.Fatal(n, err, readErr)
				}
			} else if err == nil {
				t.Fatal("unsafe or incomplete profile accepted")
			}
			if kind == "write-error" && !errors.Is(err, failure) {
				t.Fatal(err)
			}
			if (kind == "existing" || kind == "symlink" || kind == "directory-replaced") && called {
				t.Fatal("writer called before custody")
			}
			if kind == "existing" {
				data, err := os.ReadFile(name)
				if err != nil || string(data) != "original" {
					t.Fatal("existing profile overwritten", err)
				}
			}
		})
	}
}
