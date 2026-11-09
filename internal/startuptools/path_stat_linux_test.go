//go:build linux && (amd64 || arm64)

package startuptools

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestFreshPathNodeSyscallArgumentParity(t *testing.T) {
	before := mustPathInfo(t, "/usr")
	for _, path := range []string{"", "/", "/usr", "/bin/sh", "/proc/self/exe", t.TempDir() + "/absent", "/usr\x00/ignored", strings.Repeat("x", 4095), strings.Repeat("x", 4096), strings.Repeat("x", 8192)} {
		var stat syscall.Stat_t
		wantErr := syscall.Lstat(path, &stat)
		want := wantErr == nil && sameReviewedStat(before.Sys().(*syscall.Stat_t), &stat)
		got, gotErr := freshPathNode(path, before)
		if got != want || !errors.Is(gotErr, wantErr) {
			t.Fatalf("path length=%d: got=%t/%v want=%t/%v", len(path), got, gotErr, want, wantErr)
		}
	}
}

func TestFreshPathNodeActualMutationAndSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("reviewed node authority requires root ownership")
	}
	dir := t.TempDir()
	path := dir + "/node"
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	before := mustPathInfo(t, path)
	if same, err := freshPathNode(path, before); err != nil || !same {
		t.Fatalf("original node %t/%v", same, err)
	}
	if err := os.WriteFile(path, []byte("changed length"), 0600); err != nil {
		t.Fatal(err)
	}
	if same, err := freshPathNode(path, before); err != nil || same {
		t.Fatalf("mutated node accepted %t/%v", same, err)
	}
	link := dir + "/link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	linkInfo := mustPathInfo(t, link)
	if same, err := freshPathNode(link, linkInfo); err != nil || !same {
		t.Fatalf("original symlink %t/%v", same, err)
	}
	if same, err := freshPathNode(link, mustPathInfo(t, path)); err != nil || same {
		t.Fatalf("symlink followed %t/%v", same, err)
	}
	if err := os.Rename(path, dir+"/old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if same, err := freshPathNode(path, before); err != nil || same {
		t.Fatalf("replacement inode accepted %t/%v", same, err)
	}
}

func TestFreshPathNodeConcurrentArgumentsRemainExclusive(t *testing.T) {
	paths := []string{"/", "/usr", "/bin", "/bin/sh", "/proc/self/exe"}
	infos := make([]os.FileInfo, len(paths))
	wants := make([]bool, len(paths))
	for i, path := range paths {
		infos[i] = mustPathInfo(t, path)
		wants[i] = sameNode(infos[i], mustPathInfo(t, path))
	}
	missing := t.TempDir() + "/absent"
	var workers sync.WaitGroup
	errorsCh := make(chan error, 16)
	for worker := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := range 100 {
				i := (worker + iteration) % len(paths)
				if got, err := freshPathNode(paths[i], infos[i]); err != nil || got != wants[i] {
					errorsCh <- fmt.Errorf("original path %s = %t/%v", paths[i], got, err)
					return
				}
				if got, err := freshPathNode(missing, infos[i]); got || !errors.Is(err, syscall.ENOENT) {
					errorsCh <- fmt.Errorf("missing path = %t/%v", got, err)
					return
				}
			}
		}()
	}
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
}

func TestFreshPathNodeActualRootNodes(t *testing.T) {
	for _, path := range []string{"/", "/usr", "/bin", "/bin/sh", "/proc/self/exe"} {
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := freshPathNode(path, before)
		if err != nil || got != sameNode(before, after) {
			t.Fatalf("%s parity got=%t err=%v", path, got, err)
		}
	}
	if same, err := freshPathNode(t.TempDir()+"/absent", mustPathInfo(t, "/usr")); same || !os.IsNotExist(err) {
		t.Fatalf("missing path %t %v", same, err)
	}
}

func mustPathInfo(t testing.TB, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestFreshPathNodeStatComparisonFields(t *testing.T) {
	original := syscall.Stat_t{Dev: 1, Ino: 2, Mode: syscall.S_IFREG | 0600, Uid: 0, Gid: 3, Size: 4, Ctim: syscall.Timespec{Sec: 5}, Mtim: syscall.Timespec{Sec: 6}}
	for name, mutate := range map[string]func(*syscall.Stat_t){
		"device": func(s *syscall.Stat_t) { s.Dev++ }, "inode": func(s *syscall.Stat_t) { s.Ino++ },
		"mode": func(s *syscall.Stat_t) { s.Mode ^= 0100 }, "uid": func(s *syscall.Stat_t) { s.Uid++ },
		"gid": func(s *syscall.Stat_t) { s.Gid++ }, "size": func(s *syscall.Stat_t) { s.Size++ },
		"ctime": func(s *syscall.Stat_t) { s.Ctim.Nsec++ }, "mtime": func(s *syscall.Stat_t) { s.Mtim.Nsec++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if sameReviewedStat(&original, &changed) {
				t.Fatal("changed node accepted")
			}
		})
	}
	for _, mode := range []uint32{syscall.S_IFREG | 0620, syscall.S_IFREG | 0602, syscall.S_IFREG | syscall.S_ISUID | 0600, syscall.S_IFLNK | syscall.S_ISGID | 0777} {
		unsafe := original
		unsafe.Mode = mode
		if sameReviewedStat(&unsafe, &unsafe) {
			t.Fatalf("unprotected mode %o", mode)
		}
	}
	directory := original
	directory.Mode = syscall.S_IFDIR | 0755
	changed := directory
	changed.Ctim.Sec++
	changed.Mtim.Sec++
	changed.Size++
	if !sameReviewedStat(&directory, &changed) {
		t.Fatal("directory membership remains a separate check")
	}
	link := original
	link.Mode = syscall.S_IFLNK | 0777
	if !sameReviewedStat(&link, &link) {
		t.Fatal("root symlink mode")
	}
}

func BenchmarkFreshPathNode(b *testing.B) {
	path := "/usr/bin/env"
	before := mustPathInfo(b, path)
	for _, mode := range []string{"fileinfo", "before_syscall_lstat", "direct-stat"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				var ok bool
				var err error
				if mode == "fileinfo" {
					var after os.FileInfo
					after, err = os.Lstat(path)
					if err == nil {
						ok = sameNode(before, after)
					}
				} else if mode == "before_syscall_lstat" {
					var after syscall.Stat_t
					err = syscall.Lstat(path, &after)
					if err == nil {
						ok = sameReviewedStat(before.Sys().(*syscall.Stat_t), &after)
					}
				} else {
					ok, err = freshPathNode(path, before)
				}
				if err != nil || !ok {
					b.Fatalf("actual root node %t %v", ok, err)
				}
			}
		})
	}
}
