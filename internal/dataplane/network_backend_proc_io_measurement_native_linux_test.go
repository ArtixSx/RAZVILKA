//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

func backendProcFunctionBody(t *testing.T, source []byte, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			var out bytes.Buffer
			if err := format.Node(&out, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			return out.String()
		}
	}
	t.Fatal("missing exact source function", name)
	return ""
}
func backendProcSHA(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func backendProcSourceParity(t *testing.T) (string, string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source location")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(file), "network_backend_inventory_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	original := backendProcFunctionBody(t, actual, "backendInventoryThreadProcOriginalBaseline")
	if backendProcSHA([]byte(original)) != "6ee5e968ccb380856b536289daff9e689f5d6782cd21c54b43a802a1a2f4a0e7" {
		t.Fatal("frozen measured 60bd5153 original baseline changed")
	}
	expected := strings.ReplaceAll(string(actual), "\r\n", "\n")
	for _, change := range [][2]string{{backendProcOldMountIO, backendProcNewMountIO}, {backendProcOldPayloadIO, backendProcNewPayloadIO}} {
		if strings.Count(expected, change[0]) != 1 {
			t.Fatal("pinned original IO block changed")
		}
		expected = strings.Replace(expected, change[0], change[1], 1)
	}
	want := backendProcFunctionBody(t, []byte(expected), "backendInventoryThreadProcOriginalBaseline")
	got := backendProcFunctionBody(t, source, "backendInventoryThreadProc")
	if want != got {
		t.Fatal("production changed more than measured two IO blocks")
	}
	helper, err := os.ReadFile(filepath.Join(filepath.Dir(file), "network_backend_proc_read_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	if backendProcSHA([]byte(backendProcFunctionBody(t, helper, "backendInventoryReadProcBounded"))) != "d6f950084625a39f1cd0dd737c06b8f985b7a2e58a612ccb130c00e7cc3615af" {
		t.Fatal("measured bounded reader contract changed")
	}

	t.Logf("backend_proc_io_implementations baseline_revision=60bd5153e8bf3e49bfdca3d2e406ba6bfd30bab4 raw=actual-production helper_sha256=%s", backendProcSHA(helper))
	return backendProcSHA(source), backendProcSHA([]byte(original))
}
func TestBackendProcIOSourceParity(t *testing.T) {
	file, body := backendProcSourceParity(t)
	t.Logf("backend_proc_io_source file_sha256=%s original_body_sha256=%s", file, body)
}

func TestBackendProcIOBoundedRefusals(t *testing.T) { checkBackendInventoryProcReadRefusals(t) }

func backendProcIOFixture(t *testing.T, use func(context.Context, *netidentity.Provider) error) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ownNS, ownErr := os.Stat("/proc/self/ns/net")
	initNS, initErr := os.Stat("/proc/1/ns/net")
	if ownErr != nil || initErr != nil || os.SameFile(ownNS, initNS) {
		t.Fatal("explicit disposable network namespace required", ownErr, initErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Error("fixture socket close", err)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	before := unix.Gettid()
	provider := netidentity.NewProcProvider()
	if err := use(ctx, provider); err != nil {
		t.Fatal(err)
	}
	if unix.Gettid() != before {
		t.Fatal("measurement changed OS thread")
	}
}

func TestBackendProcIOActualPairs(t *testing.T) {
	if os.Getenv("RAZVILKA_BACKEND_PROC_IO_MEASURE") != "1" {
		t.Skip("explicit isolated leaf comparison only")
	}
	fileSHA, bodySHA := backendProcSourceParity(t)
	backendProcIOFixture(t, func(ctx context.Context, provider *netidentity.Provider) error {
		var expected []byte
		if err := provider.WithCurrent(ctx, func(held context.Context, _ netidentity.Identity) error {
			var err error
			expected, err = backendInventoryThreadProcOriginalBaseline(held, backendThreadNetlink)
			if err != nil {
				return err
			}
			got, err := backendInventoryThreadProc(held, backendThreadNetlink)
			if err != nil || !bytes.Equal(got, expected) {
				return errors.Join(errBackendInventory, err)
			}
			return nil
		}); err != nil {
			return err
		}
		for pair := 0; pair < 8; pair++ {
			order := []string{"original", "raw"}
			if pair%2 != 0 {
				order = []string{"raw", "original"}
			}
			for _, mode := range order {
				var wall, cpu int64
				providerStart := time.Now()
				err := provider.WithCurrent(ctx, func(held context.Context, _ netidentity.Identity) error {
					var before, after unix.Rusage
					if err := unix.Getrusage(unix.RUSAGE_THREAD, &before); err != nil {
						return err
					}
					start := time.Now()
					for call := 0; call < 64; call++ {
						var got []byte
						var err error
						if mode == "original" {
							got, err = backendInventoryThreadProcOriginalBaseline(held, backendThreadNetlink)
						} else {
							got, err = backendInventoryThreadProc(held, backendThreadNetlink)
						}
						if err != nil || !bytes.Equal(got, expected) {
							return errors.Join(errBackendInventory, err)
						}
					}
					wall = time.Since(start).Nanoseconds()
					if err := unix.Getrusage(unix.RUSAGE_THREAD, &after); err != nil {
						return err
					}
					cpu = (after.Utime.Nano() + after.Stime.Nano()) - (before.Utime.Nano() + before.Stime.Nano())
					return nil
				})
				providerNS := time.Since(providerStart).Nanoseconds()
				if err != nil {
					return err
				}
				row := map[string]any{"baseline_revision": "60bd5153e8bf3e49bfdca3d2e406ba6bfd30bab4", "raw_implementation": "actual-production", "pair": pair, "mode": mode, "calls": 64, "wall_ns": wall, "thread_cpu_ns": cpu, "provider_bracket_ns": providerNS, "bytes": len(expected), "payload_sha256": backendProcSHA(expected), "source_sha256": fileSHA, "original_body_sha256": bodySHA}
				data, _ := json.Marshal(row)
				t.Logf("backend_proc_io_pair %s", data)
			}
		}
		return nil
	})
}

// Separate tracing population: frozen original versus actual production. Provider setup/closing and Go startup are
// outside fixed BEGIN/END markers on the same locked OS thread.
func TestBackendProcIOTrace(t *testing.T) {
	mode := os.Getenv("RAZVILKA_BACKEND_PROC_IO_TRACE")
	if mode == "" {
		t.Skip("separate diagnostic trace only")
	}
	if mode != "original" && mode != "raw" {
		t.Fatal("closed trace mode")
	}
	backendProcSourceParity(t)
	backendProcIOFixture(t, func(ctx context.Context, provider *netidentity.Provider) error {
		return provider.WithCurrent(ctx, func(held context.Context, _ netidentity.Identity) error {
			if _, err := unix.Write(2, []byte("BACKEND_PROC_IO_BEGIN\n")); err != nil {
				return err
			}
			var data []byte
			var err error
			if mode == "original" {
				data, err = backendInventoryThreadProcOriginalBaseline(held, backendThreadNetlink)
			} else {
				data, err = backendInventoryThreadProc(held, backendThreadNetlink)
			}
			_, closing := unix.Write(2, []byte("BACKEND_PROC_IO_END\n"))
			if err != nil || closing != nil {
				return errors.Join(err, closing)
			}
			if len(data) == 0 {
				return errBackendInventory
			}
			return nil
		})
	})
}

const backendProcOldMountIO = "\t\tfile := os.NewFile(uintptr(f), \"proc-fdinfo\")\n\t\tif file == nil {\n\t\t\t_ = unix.Close(f)\n\t\t\treturn \"\", errBackendInventory\n\t\t}\n\t\tif !check(f, false) {\n\t\t\t_ = file.Close()\n\t\t\treturn \"\", errBackendInventory\n\t\t}\n\t\tdata, readErr := io.ReadAll(io.LimitReader(file, 4097))\n\t\tcloseErr := file.Close()"
const backendProcNewMountIO = "\t\tif !check(f, false) {\n\t\t\t_ = unix.Close(f)\n\t\t\treturn \"\", errBackendInventory\n\t\t}\n\t\tdata, readErr := backendInventoryReadProcFD(ctx, f, 4096)\n\t\tcloseErr := unix.Close(f)"
const backendProcOldPayloadIO = "\t// Duplicate ownership for os.File; retained FD is used for closing checks.\n\tdup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tfile := os.NewFile(uintptr(dup), \"classic-table-names\")\n\tdata, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))\n\tcloseErr := file.Close()\n\tif readErr != nil || closeErr != nil || len(data) > limit || ctx.Err() != nil || unix.Getpid() != pid || unix.Gettid() != tid {\n\t\treturn nil, errors.Join(errBackendInventory, readErr, closeErr, ctx.Err())\n\t}"
const backendProcNewPayloadIO = "\t// The same retained FD remains owned until all original closing checks.\n\tdata, readErr := backendInventoryReadProcFD(ctx, fd, limit)\n\tif readErr != nil || len(data) > limit || ctx.Err() != nil || unix.Getpid() != pid || unix.Gettid() != tid {\n\t\treturn nil, errors.Join(errBackendInventory, readErr, ctx.Err())\n\t}"

// Frozen original leaf from 60bd5153; diagnostic baseline only.
func backendInventoryThreadProcOriginalBaseline(ctx context.Context, which backendThreadProcFile) (result []byte, resultErr error) {
	name, limit := "ip_tables_names", backendClassicNamesBytes
	pid, tid := unix.Getpid(), unix.Gettid()
	parts := []string{strconv.Itoa(pid), "task", strconv.Itoa(tid), "net"}
	switch which {
	case backendThreadTables4:
	case backendThreadTables6:
		name = "ip6_tables_names"
	case backendThreadQueues:
		parts = append(parts, "netfilter")
		name, limit = "nfnetlink_queue", 1<<20
	case backendThreadNetlink:
		name, limit = "netlink", 1<<20
	default:
		return nil, errBackendInventory
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, errBackendInventory
	}
	const dirs = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	root, err := unix.Open("/proc", dirs, 0)
	if err != nil {
		return nil, err
	}
	fds := []int{root}
	defer func() {
		var closing error
		for i := len(fds) - 1; i >= 0; i-- {
			closing = errors.Join(closing, unix.Close(fds[i]))
		}
		if closing != nil {
			result = nil
			resultErr = errors.Join(errBackendInventory, resultErr, closing)
		}
	}()
	var rootStat unix.Stat_t
	var rootFS unix.Statfs_t
	if unix.Fstat(root, &rootStat) != nil || unix.Fstatfs(root, &rootFS) != nil || rootStat.Ino != 1 || rootFS.Type != unix.PROC_SUPER_MAGIC || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errBackendInventory
	}
	check := func(fd int, directory bool) bool {
		var st unix.Stat_t
		var fs unix.Statfs_t
		want := uint32(unix.S_IFREG)
		if directory {
			want = unix.S_IFDIR
		}
		return unix.Fstat(fd, &st) == nil && unix.Fstatfs(fd, &fs) == nil && st.Mode&unix.S_IFMT == want && st.Dev == rootStat.Dev && fs.Type == rootFS.Type && fs.Fsid == rootFS.Fsid
	}
	parent := root
	var pidFD int
	for i, part := range parts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fd, err := unix.Openat(parent, part, dirs, 0)
		if err != nil {
			return nil, err
		}
		fds = append(fds, fd)
		if !check(fd, true) {
			return nil, errBackendInventory
		}
		if i == 0 {
			pidFD = fd
		}
		parent = fd
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fds = append(fds, fd)
	if !check(fd, false) {
		return nil, errBackendInventory
	}
	info, err := unix.Openat(pidFD, "fdinfo", dirs, 0)
	if err != nil {
		return nil, err
	}
	fds = append(fds, info)
	if !check(info, true) {
		return nil, errBackendInventory
	}
	mount := func(descriptor int) (string, error) {
		f, err := unix.Openat(info, strconv.Itoa(descriptor), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return "", err
		}
		file := os.NewFile(uintptr(f), "proc-fdinfo")
		if file == nil {
			_ = unix.Close(f)
			return "", errBackendInventory
		}
		if !check(f, false) {
			_ = file.Close()
			return "", errBackendInventory
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 4096 {
			return "", errBackendInventory
		}
		return backendInventoryProcMountID(data)
	}
	rootMount, err := mount(root)
	if err != nil {
		return nil, err
	}
	for _, f := range fds {
		if got, err := mount(f); err != nil || got != rootMount {
			return nil, errBackendInventory
		}
	}
	// Duplicate ownership for os.File; retained FD is used for closing checks.
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(dup), "classic-table-names")
	data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > limit || ctx.Err() != nil || unix.Getpid() != pid || unix.Gettid() != tid {
		return nil, errors.Join(errBackendInventory, readErr, closeErr, ctx.Err())
	}
	for i, f := range fds {
		if !check(f, i != len(fds)-2) {
			return nil, errBackendInventory
		}
		if got, err := mount(f); err != nil || got != rootMount {
			return nil, errBackendInventory
		}
	}
	return data, nil
}
