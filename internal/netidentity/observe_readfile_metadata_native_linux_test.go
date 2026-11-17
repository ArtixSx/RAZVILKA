//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Measurement only: no production caller, syscall hook, cache or changed
// captureProc/stable/mountsMatch traversal. The two full leaf bodies below are
// mechanically compared with the checked-in producer.
//
//go:embed observe_linux.go
var readFileMetadataProduction string

//go:embed observe_readfile_metadata_native_linux_test.go
var readFileMetadataExperiment string

const readFileMetadataMask = unix.STATX_TYPE | unix.STATX_MNT_ID

type readFileMetadataNativeCounts struct{ fast, fallback int }

func (a *audit) readFileCombinedNative(parent int, name string, limit int, rootMount uint64, counts ...*readFileMetadataNativeCounts) ([]byte, bool) {
	if a.ctx.Err() != nil || !component(name) {
		return nil, false
	}
	fd, err := syscall.Openat(parent, name, fileFlags, 0)
	if err != nil {
		return nil, false
	}
	defer syscall.Close(fd)
	var stat unix.Statx_t
	callErr := unix.Statx(fd, "", unix.AT_EMPTY_PATH, readFileMetadataMask, &stat)
	if !a.readFileMetadataNative(fd, rootMount, stat, callErr, counts...) {
		return nil, false
	}
	return boundedRead(a.ctx, fd, limit)
}

func (a *audit) readFileMetadataNative(fd int, rootMount uint64, stat unix.Statx_t, callErr error, counts ...*readFileMetadataNativeCounts) bool {
	var count *readFileMetadataNativeCounts
	if len(counts) == 1 {
		count = counts[0]
	}
	if callErr != nil {
		switch callErr {
		case unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL, unix.EPERM, unix.EACCES:
			if count != nil {
				count.fallback++
			}
			return a.readFileOriginalMetadataNative(fd, rootMount)
		default:
			return false
		}
	}
	// A supplied invalid mount ID is malformed, even when another requested
	// field is missing. It must not enter the unsupported-field fallback.
	if stat.Mask&unix.STATX_MNT_ID != 0 && stat.Mnt_id == 0 {
		return false
	}
	if stat.Mask&readFileMetadataMask != readFileMetadataMask {
		if count != nil {
			count.fallback++
		}
		return a.readFileOriginalMetadataNative(fd, rootMount)
	}
	if count != nil {
		count.fast++
	}
	var fs syscall.Statfs_t
	return syscall.Fstatfs(fd, &fs) == nil && stat.Mode&syscall.S_IFMT == syscall.S_IFREG &&
		fs.Type == procMagic && unix.Mkdev(stat.Dev_major, stat.Dev_minor) == uint64(a.root.stat.Dev) && fs.Fsid == a.root.fs.Fsid &&
		stat.Mnt_id != 0 && stat.Mnt_id == rootMount && a.ctx.Err() == nil
}

func (a *audit) readFileOriginalMetadataNative(fd int, rootMount uint64) bool {
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &st) != nil || syscall.Fstatfs(fd, &fs) != nil ||
		st.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Type != procMagic ||
		st.Dev != a.root.stat.Dev || fs.Fsid != a.root.fs.Fsid {
		return false
	}
	id, ok := a.mountID(fd)
	return ok && id == rootMount
}

func readFileMetadataBody(t *testing.T, source, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			var b bytes.Buffer
			if err := format.Node(&b, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			// A removed comment can leave a blank source-position line. Ignore
			// blank lines only; every remaining token and predicate stays exact.
			return strings.ReplaceAll(b.String(), "\n\n", "\n")
		}
	}
	t.Fatal("source function absent", name)
	return ""
}

func TestReadFileMetadataNativeSourceParity(t *testing.T) {
	original := readFileMetadataBody(t, readFileMetadataProduction, "readFile")
	candidate := readFileMetadataBody(t, readFileMetadataExperiment, "readFileCombinedNative")
	start, end := strings.Index(original, "\tvar st syscall.Stat_t"), strings.Index(original, "\treturn boundedRead")
	cs, ce := strings.Index(candidate, "\tvar stat unix.Statx_t"), strings.Index(candidate, "\treturn boundedRead")
	if start < 0 || end <= start || cs < 0 || ce <= cs || original[:start] != candidate[:cs] || original[end:] != candidate[ce:] {
		t.Fatal("candidate changed original opening, read, close or refusal structure")
	}
	// Pin the removed block, not a second generated baseline. All its original
	// predicates remain in the fallback helper and in the combined comparison.
	want := "\tvar st syscall.Stat_t\n\tvar fs syscall.Statfs_t\n\tif syscall.Fstat(fd, &st) != nil || syscall.Fstatfs(fd, &fs) != nil ||\n\t\tst.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Type != procMagic ||\n\t\tst.Dev != a.root.stat.Dev || fs.Fsid != a.root.fs.Fsid {\n\t\treturn nil, false\n\t}\n\tid, ok := a.mountID(fd)\n\tif !ok || id != rootMount {\n\t\treturn nil, false\n\t}\n"
	if original[start:end] != want {
		t.Fatal("original metadata predicates changed")
	}
	t.Logf("READFILE_SOURCE original_body_sha256=%x candidate_body_sha256=%x production_file_sha256=%x", sha256.Sum256([]byte(original)), sha256.Sum256([]byte(candidate)), sha256.Sum256([]byte(readFileMetadataProduction)))
}

func readFileMetadataFixture(t *testing.T, ctx context.Context) (*audit, int, uint64) {
	t.Helper()
	a := mountIDAuditFixture(t, ctx)
	pid, ok := a.openDir(a.root.fd, strconv.Itoa(os.Getpid()))
	if !ok {
		t.Fatal("original PID directory")
	}
	mount, ok := a.mountID(a.root.fd)
	if !ok || !a.stable() || !a.mountsMatch(mount) {
		t.Fatal("opening original audit")
	}
	return a, pid, mount
}

func TestReadFileMetadataNativeResultBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a, pid, mount := readFileMetadataFixture(t, ctx)
	fd, err := syscall.Openat(pid, "comm", fileFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, readFileMetadataMask, &stat); err != nil || stat.Mask&readFileMetadataMask != readFileMetadataMask {
		t.Fatal("actual combined statx unsupported", err)
	}
	var old syscall.Stat_t
	if syscall.Fstat(fd, &old) != nil || uint32(stat.Mode)&syscall.S_IFMT != old.Mode&syscall.S_IFMT || unix.Mkdev(stat.Dev_major, stat.Dev_minor) != uint64(old.Dev) || stat.Mnt_id != mount {
		t.Fatal("fresh original metadata mismatch")
	}
	if !a.readFileMetadataNative(fd, mount, stat, nil) {
		t.Fatal("actual metadata")
	}
	for _, err := range []error{unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL, unix.EPERM, unix.EACCES} {
		if !a.readFileMetadataNative(fd, mount, unix.Statx_t{}, err) {
			t.Fatal("original fallback", err)
		}
	}
	for _, missing := range []uint32{unix.STATX_TYPE, unix.STATX_MNT_ID} {
		partial := stat
		partial.Mask &^= missing
		partial.Mnt_id = mount + 1
		if !a.readFileMetadataNative(fd, mount, partial, nil) {
			t.Fatal("partial fields bypassed original fallback")
		}
	}
	mixed := stat
	mixed.Mask &^= unix.STATX_TYPE
	mixed.Mnt_id = 0
	if a.readFileMetadataNative(fd, mount, mixed, nil) {
		t.Fatal("present zero mount ID escaped through missing type fallback")
	}
	if _, ok := a.readFile(pid, "comm", 64, mount+1); ok {
		t.Fatal("original accepted wrong actual leaf mount")
	}
	if _, ok := a.readFileCombinedNative(pid, "comm", 64, mount+1); ok {
		t.Fatal("candidate accepted wrong actual leaf mount")
	}
	for _, mutate := range []func(*unix.Statx_t){func(s *unix.Statx_t) { s.Mnt_id = 0 }, func(s *unix.Statx_t) { s.Mnt_id++ }, func(s *unix.Statx_t) { s.Mode = unix.S_IFDIR }, func(s *unix.Statx_t) { s.Dev_minor++ }} {
		bad := stat
		mutate(&bad)
		if a.readFileMetadataNative(fd, mount, bad, nil) {
			t.Fatal("malformed supported result accepted")
		}
	}
	for _, err := range []error{unix.EIO, unix.EBADF, unix.ESTALE, unix.EINTR} {
		if a.readFileMetadataNative(fd, mount, stat, err) {
			t.Fatal("real read error fell back", err)
		}
	}
	for _, name := range []string{"../comm", "does-not-exist", "fd"} {
		_, oldOK := a.readFile(pid, name, 64, mount)
		_, newOK := a.readFileCombinedNative(pid, name, 64, mount)
		if oldOK || newOK {
			t.Fatal("invalid leaf accepted", name)
		}
	}
	for _, limit := range []int{0, 1, 64} {
		x, okX := a.readFile(pid, "comm", limit, mount)
		y, okY := a.readFileCombinedNative(pid, "comm", limit, mount)
		if okX != okY || !bytes.Equal(x, y) {
			t.Fatal("limit/full bytes changed", limit)
		}
	}
	if !a.stable() || !a.mountsMatch(mount) {
		t.Fatal("closing original audit")
	}
	cancel()
	if a.readFileMetadataNative(fd, mount, stat, nil) {
		t.Fatal("cancellation ignored")
	}
	if _, ok := a.readFileCombinedNative(pid, "comm", 64, mount); ok {
		t.Fatal("canceled read")
	}
}

func TestReadFileMetadataNativePairedMeasurement(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, pid, mount := readFileMetadataFixture(t, ctx)
	task, ok := a.openDir(pid, "task")
	if !ok {
		t.Fatal("actual task directory")
	}
	tid := syscall.Gettid()
	thread, ok := a.openDir(task, strconv.Itoa(tid))
	if !ok {
		t.Fatal("actual held thread directory")
	}
	pid = thread
	want, ok := a.readFile(pid, "comm", 64, mount)
	if !ok || len(want) == 0 {
		t.Fatal("stable actual proc leaf")
	}
	// No whole-observation result is synthesized by the leaf experiment.
	if _, err := readObservation(ctx); err != nil {
		t.Fatal("opening full original observation", err)
	}
	const n = 512
	for pair := 0; pair < 8; pair++ {
		order := []string{"original", "combined"}
		if pair%2 == 1 {
			order = []string{"combined", "original"}
		}
		for _, variant := range order {
			counts := readFileMetadataNativeCounts{}
			read := a.readFile
			if variant == "combined" {
				read = func(parent int, name string, limit int, rootMount uint64) ([]byte, bool) {
					return a.readFileCombinedNative(parent, name, limit, rootMount, &counts)
				}
			}
			var before, after unix.Timespec
			if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &before) != nil {
				t.Fatal("thread clock")
			}
			start := time.Now()
			for range n {
				got, ok := read(pid, "comm", 64, mount)
				if !ok || !bytes.Equal(got, want) {
					t.Fatal("fresh complete leaf changed", variant)
				}
			}
			wall := time.Since(start)
			if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &after) != nil {
				t.Fatal("thread clock")
			}
			if variant == "combined" && (counts.fast != n || counts.fallback != 0) {
				t.Fatal("candidate did not use measured fast path", counts)
			}
			row := map[string]any{"pair": pair, "variant": variant, "samples": n, "fast_calls": counts.fast, "fallback_calls": counts.fallback, "wall_ns": wall.Nanoseconds(), "thread_cpu_ns": after.Nano() - before.Nano(), "bytes_per_read": len(want), "payload_sha256": fmt.Sprintf("%x", sha256.Sum256(want)), "scope": "actual-proc-thread-comm-full-leaf-open-read-close; not whole-observation or route timing"}
			encoded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("READFILE_METADATA_PAIR " + string(encoded))
		}
		if !a.stable() || !a.mountsMatch(mount) {
			t.Fatal("pair closing audit")
		}
	}
	closing, ok := a.readFile(pid, "comm", 64, mount)
	if !ok || !bytes.Equal(closing, want) || syscall.Gettid() != tid {
		t.Fatal("thread/name changed during population")
	}
	if _, err := readObservation(ctx); err != nil {
		t.Fatal("closing full original observation", err)
	}
}
