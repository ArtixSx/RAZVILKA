//go:build linux

package updatecheck

import (
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

type spaceTestEntry struct {
	name      string
	mode      os.FileMode
	size      int64
	infoErr   error
	infoCalls *int
}

func (e spaceTestEntry) Name() string      { return e.name }
func (e spaceTestEntry) IsDir() bool       { return e.mode.IsDir() }
func (e spaceTestEntry) Type() os.FileMode { return e.mode.Type() }
func (e spaceTestEntry) Info() (os.FileInfo, error) {
	if e.infoCalls != nil {
		(*e.infoCalls)++
	}
	if e.infoErr != nil {
		return nil, e.infoErr
	}
	return spaceTestInfo{e}, nil
}

type spaceTestInfo struct{ spaceTestEntry }

func (e spaceTestInfo) Size() int64        { return e.size }
func (e spaceTestInfo) Mode() os.FileMode  { return e.mode }
func (e spaceTestInfo) ModTime() time.Time { return time.Time{} }
func (e spaceTestInfo) Sys() any           { return nil }

func spaceTestRoots() []string { return []string{"config", "dataplane", "staging", "dns"} }

func spaceTestNeeded(archive, backup int64) uint64 {
	return uint64(archive + MaximumBinaryBytes*2 + backup*2 + 32<<20)
}

func requireSpaceCode(t *testing.T, err error, code string) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
		return
	}
	if err == nil || err.Error() != code {
		t.Fatalf("got %v, want %q", err, code)
	}
}

func TestUpdateSpaceMissingInfoRestartsEveryRootAndTotal(t *testing.T) {
	for _, insufficient := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh-capacity-pass", true: "fresh-capacity-refused"}[insufficient], func(t *testing.T) {
			roots := spaceTestRoots()
			statCalls := 0
			stat := func(path string) (uint64, int64, error) {
				if path != "update-cache" {
					t.Fatalf("wrong Statfs target: %q", path)
				}
				statCalls++
				if statCalls == 1 {
					return math.MaxUint64, 1, nil
				}
				available := spaceTestNeeded(1, 1000)
				if insufficient {
					available--
				}
				return available, 1, nil
			}
			var visited []string
			missingCalls := 0
			walk := func(root string, visit fs.WalkDirFunc) error {
				visited = append(visited, root)
				if statCalls == 1 {
					switch root {
					case roots[0]:
						return visit(root+"/large", spaceTestEntry{size: 2 << 30}, nil)
					case roots[1]:
						for i := 0; i < 19000; i++ {
							if err := visit(root+"/entry", spaceTestEntry{}, nil); err != nil {
								return err
							}
						}
					case roots[3]:
						return visit(root+"/.transaction-gone", spaceTestEntry{infoErr: &os.PathError{Op: "lstat", Path: "private-temp", Err: os.ErrNotExist}, infoCalls: &missingCalls}, nil)
					}
					return nil
				}
				if root == roots[0] {
					for i := 0; i < 1500; i++ {
						if err := visit(root+"/new-entry", spaceTestEntry{}, nil); err != nil {
							return err
						}
					}
				}
				for i, expected := range roots {
					if root == expected {
						return visit(root+"/fresh", spaceTestEntry{size: int64(i+1) * 100}, nil)
					}
				}
				panic("unknown root")
			}
			err := checkUpdateSpaceScan("update-cache", 1, roots, stat, walk)
			code := ""
			if insufficient {
				code = "insufficient-update-space"
			}
			requireSpaceCode(t, err, code)
			if statCalls != 2 || missingCalls != 1 || !reflect.DeepEqual(visited, append(append([]string{}, roots...), roots...)) {
				t.Fatalf("not exactly two complete scans: stats=%d missing=%d roots=%v", statCalls, missingCalls, visited)
			}
		})
	}
}

func TestUpdateSpaceRepeatedMissingInfoStopsAtTwoAttempts(t *testing.T) {
	stats, walks, infos := 0, 0, 0
	err := checkUpdateSpaceScan("cache", 1, spaceTestRoots(), func(string) (uint64, int64, error) {
		stats++
		return math.MaxUint64, 1, nil
	}, func(root string, visit fs.WalkDirFunc) error {
		walks++
		return visit(root+"/gone", spaceTestEntry{infoErr: syscall.ENOENT, infoCalls: &infos}, nil)
	})
	requireSpaceCode(t, err, "update-backup-entry-missing")
	if stats != 2 || walks != 2 || infos != 2 {
		t.Fatalf("unbounded or skipped retry: stats=%d walks=%d infos=%d", stats, walks, infos)
	}
}

func TestUpdateSpaceRetryStatRefusalStopsScan(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		stats, walks := 0, 0
		err := checkUpdateSpaceScan("cache", 1, spaceTestRoots(), func(string) (uint64, int64, error) {
			stats++
			if stats == 2 {
				if unavailable {
					return 0, 1, syscall.EIO
				}
				return math.MaxUint64, 0, nil
			}
			return math.MaxUint64, 1, nil
		}, func(root string, visit fs.WalkDirFunc) error {
			walks++
			return visit(root, spaceTestEntry{infoErr: os.ErrNotExist}, nil)
		})
		requireSpaceCode(t, err, "update-space-unavailable")
		if stats != 2 || walks != 1 {
			t.Fatalf("walk after failed retry Statfs: stats=%d walks=%d", stats, walks)
		}
	}
}

func TestUpdateSpaceOtherErrorsNeverRetry(t *testing.T) {
	for _, cause := range []error{syscall.EACCES, syscall.EIO, syscall.ENOTDIR} {
		for _, boundary := range []string{"info", "callback", "walk"} {
			t.Run(boundary+"/"+cause.Error(), func(t *testing.T) {
				stats, walks := 0, 0
				err := checkUpdateSpaceScan("cache", 1, spaceTestRoots(), func(string) (uint64, int64, error) {
					stats++
					return math.MaxUint64, 1, nil
				}, func(root string, visit fs.WalkDirFunc) error {
					walks++
					privateErr := &os.PathError{Op: boundary, Path: "private-path", Err: cause}
					switch boundary {
					case "info":
						return visit(root, spaceTestEntry{infoErr: privateErr}, nil)
					case "callback":
						return visit(root, nil, privateErr)
					default:
						return privateErr
					}
				})
				requireSpaceCode(t, err, "update-backup-space-unavailable")
				if stats != 1 || walks != 1 {
					t.Fatalf("retried %s: stats=%d walks=%d", boundary, stats, walks)
				}
			})
		}
	}
	// ENOENT returned by WalkDir itself does not establish the Info race.
	stats := 0
	err := checkUpdateSpaceScan("cache", 1, spaceTestRoots(), func(string) (uint64, int64, error) {
		stats++
		return math.MaxUint64, 1, nil
	}, func(string, fs.WalkDirFunc) error { return os.ErrNotExist })
	requireSpaceCode(t, err, "update-backup-space-unavailable")
	if stats != 1 {
		t.Fatal("raw walk ENOENT caused a rescan")
	}
}

func TestUpdateSpaceRetryRetainsEveryRefusal(t *testing.T) {
	for _, refusal := range []string{"symlink", "count", "bytes", "negative-size", "huge-size", "info-error", "walk-error"} {
		for _, afterMissing := range []bool{false, true} {
			t.Run(refusal+map[bool]string{false: "/first", true: "/rescan"}[afterMissing], func(t *testing.T) {
				stats, missingInfos, refusedInfos := 0, 0, 0
				roots := spaceTestRoots()
				var visited []string
				err := checkUpdateSpaceScan("cache", 1, roots, func(string) (uint64, int64, error) {
					stats++
					return math.MaxUint64, 1, nil
				}, func(root string, visit fs.WalkDirFunc) error {
					visited = append(visited, root)
					if afterMissing && stats == 1 {
						return visit(root, spaceTestEntry{infoErr: os.ErrNotExist, infoCalls: &missingInfos}, nil)
					}
					switch refusal {
					case "symlink":
						return visit(root, spaceTestEntry{mode: os.ModeSymlink, infoErr: os.ErrNotExist, infoCalls: &refusedInfos}, nil)
					case "count":
						count := 10000
						if root == roots[1] {
							count++
						}
						for i := 0; i < count; i++ {
							entry := spaceTestEntry{}
							if root == roots[1] && i == count-1 {
								entry.infoErr, entry.infoCalls = os.ErrNotExist, &refusedInfos
							}
							if err := visit(root, entry, nil); err != nil {
								return err
							}
						}
						return nil
					case "bytes":
						size := int64(1 << 30)
						if root == roots[2] {
							size = 1
						}
						return visit(root, spaceTestEntry{size: size}, nil)
					case "negative-size":
						return visit(root, spaceTestEntry{size: -1}, nil)
					case "huge-size":
						if root == roots[0] {
							return visit(root, spaceTestEntry{size: 1}, nil)
						}
						return visit(root, spaceTestEntry{size: math.MaxInt64}, nil)
					case "info-error":
						return visit(root, spaceTestEntry{infoErr: syscall.EIO}, nil)
					default:
						return syscall.EACCES
					}
				})
				requireSpaceCode(t, err, "update-backup-space-unavailable")
				wantStats := 1
				if afterMissing {
					wantStats = 2
				}
				if stats != wantStats || refusedInfos != 0 || missingInfos != wantStats-1 {
					t.Fatalf("refusal weakened: stats=%d missing=%d refusedInfo=%d", stats, missingInfos, refusedInfos)
				}
				wantRoots := 1
				if refusal == "count" || refusal == "huge-size" {
					wantRoots = 2
				} else if refusal == "bytes" {
					wantRoots = 3
				}
				expected := append([]string{}, roots[:wantRoots]...)
				if afterMissing {
					expected = append([]string{roots[0]}, expected...)
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("wrong refusal boundary: visited=%v want=%v", visited, expected)
				}
			})
		}
	}
}

func TestUpdateSpaceMissingRootsAndDirectoriesKeepPriorHandling(t *testing.T) {
	stats, walks, infos := 0, 0, 0
	err := checkUpdateSpaceScan("cache", 1, spaceTestRoots(), func(string) (uint64, int64, error) {
		stats++
		return spaceTestNeeded(1, 0), 1, nil
	}, func(root string, visit fs.WalkDirFunc) error {
		walks++
		if err := visit(root+"/absent", nil, &os.PathError{Err: os.ErrNotExist}); err != nil {
			return err
		}
		return visit(root, spaceTestEntry{mode: os.ModeDir, infoErr: syscall.EIO, infoCalls: &infos}, nil)
	})
	requireSpaceCode(t, err, "")
	if stats != 1 || walks != 4 || infos != 0 {
		t.Fatalf("changed prior directory behavior: stats=%d walks=%d infos=%d", stats, walks, infos)
	}
}

func TestUpdateSpaceBoundsAndBlockArithmetic(t *testing.T) {
	archive := MaximumArchiveBytes - 1 // Exercises non-aligned block rounding.
	needed := spaceTestNeeded(archive, 2<<30)
	for _, tc := range []struct {
		name    string
		blocks  uint64
		size    int64
		statErr error
		code    string
	}{
		{"exact", needed, 1, nil, ""},
		{"one-byte-short", needed - 1, 1, nil, "insufficient-update-space"},
		{"rounded-up", needed/4096 + 1, 4096, nil, ""},
		{"rounded-down", needed / 4096, 4096, nil, "insufficient-update-space"},
		{"multiplication-overflow", math.MaxUint64, 4096, nil, ""},
		{"large-block", 1, math.MaxInt64, nil, ""},
		{"large-block-empty", 0, math.MaxInt64, nil, "insufficient-update-space"},
		{"zero-block-size", math.MaxUint64, 0, nil, "update-space-unavailable"},
		{"negative-block-size", math.MaxUint64, -1, nil, "update-space-unavailable"},
		{"stat-refused", math.MaxUint64, 1, syscall.EIO, "update-space-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats, walks, entries := 0, 0, 0
			err := checkUpdateSpaceScan("cache", archive, spaceTestRoots(), func(string) (uint64, int64, error) {
				stats++
				return tc.blocks, tc.size, tc.statErr
			}, func(root string, visit fs.WalkDirFunc) error {
				walks++
				for i := 0; i < 5000; i++ {
					entry := spaceTestEntry{}
					if entries == 0 {
						entry.size = 2 << 30
					}
					entries++
					if err := visit(root, entry, nil); err != nil {
						return err
					}
				}
				return nil
			})
			requireSpaceCode(t, err, tc.code)
			wantWalks := 4
			if tc.statErr != nil || tc.size <= 0 {
				wantWalks = 0
			}
			if stats != 1 || walks != wantWalks {
				t.Fatalf("unexpected scan count: stats=%d walks=%d", stats, walks)
			}
		})
	}
	for _, archive := range []int64{-1, 0, MaximumArchiveBytes + 1, math.MaxInt64} {
		err := checkUpdateSpaceScan("cache", archive, spaceTestRoots(), func(string) (uint64, int64, error) {
			t.Fatal("invalid archive reached Statfs")
			return 0, 0, nil
		}, func(string, fs.WalkDirFunc) error {
			t.Fatal("invalid archive reached walk")
			return nil
		})
		requireSpaceCode(t, err, "asset-size-or-digest-invalid")
	}
	for _, archive := range []int64{1, MaximumArchiveBytes} {
		requireSpaceCode(t, checkUpdateSpaceScan("cache", archive, nil, func(string) (uint64, int64, error) {
			return spaceTestNeeded(archive, 0), 1, nil
		}, filepath.WalkDir), "")
	}
}

func TestUpdateSpaceRealWalk(t *testing.T) {
	base := t.TempDir()
	roots := []string{filepath.Join(base, "config"), filepath.Join(base, "dataplane"), filepath.Join(base, "staging"), filepath.Join(base, "missing-dns")}
	for _, root := range roots[:3] {
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte("retained settings")
	if err := os.WriteFile(filepath.Join(roots[0], "settings"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	available := spaceTestNeeded(1, int64(len(payload)))
	stat := func(string) (uint64, int64, error) { return available, 1, nil }
	requireSpaceCode(t, checkUpdateSpaceScan(base, 1, roots, stat, filepath.WalkDir), "")
	available--
	requireSpaceCode(t, checkUpdateSpaceScan(base, 1, roots, stat, filepath.WalkDir), "insufficient-update-space")
	if err := os.Symlink(filepath.Join(roots[0], "settings"), filepath.Join(roots[1], "link")); err != nil {
		t.Fatal(err)
	}
	available++
	requireSpaceCode(t, checkUpdateSpaceScan(base, 1, roots, stat, filepath.WalkDir), "update-backup-space-unavailable")
}

type spaceRenameEntry struct {
	os.DirEntry
	rename func() error
}

func (e spaceRenameEntry) Info() (os.FileInfo, error) {
	if err := e.rename(); err != nil {
		return nil, err
	}
	return e.DirEntry.Info()
}

func TestUpdateSpaceRealAtomicRenameBetweenReadDirAndInfo(t *testing.T) {
	root := t.TempDir()
	temporary := filepath.Join(root, ".transaction-fixture")
	committed := filepath.Join(root, "settings")
	payload := []byte("committed settings")
	if err := os.WriteFile(temporary, payload, 0600); err != nil {
		t.Fatal(err)
	}
	stats, renames, walks := 0, 0, 0
	stat := func(string) (uint64, int64, error) {
		stats++
		return spaceTestNeeded(1, int64(len(payload))), 1, nil
	}
	walk := func(root string, visit fs.WalkDirFunc) error {
		walks++
		return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if path == temporary && err == nil {
				entry = spaceRenameEntry{DirEntry: entry, rename: func() error {
					renames++
					return os.Rename(temporary, committed)
				}}
			}
			return visit(path, entry, err)
		})
	}
	requireSpaceCode(t, checkUpdateSpaceScan(root, 1, []string{root}, stat, walk), "")
	if stats != 2 || walks != 2 || renames != 1 {
		t.Fatalf("actual rename race not observed: stats=%d walks=%d renames=%d", stats, walks, renames)
	}
	actual, err := os.ReadFile(committed)
	if err != nil || string(actual) != string(payload) {
		t.Fatalf("committed file changed: %q, %v", actual, err)
	}
}
