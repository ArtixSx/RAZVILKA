//go:build linux && (amd64 || arm64)

package startuptools

import (
	"os"
	"syscall"
	"testing"
)

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
	for _, mode := range []string{"fileinfo", "direct-stat"} {
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
