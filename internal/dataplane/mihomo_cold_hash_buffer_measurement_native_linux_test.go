//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Measurement only. Every file open, full read, SHA, EOF and identity bookend
// is unchanged. Only one private read buffer is used for two synchronous reads.
// No digest, file view, callback or authority is reused across observations.
//
//go:embed mihomo_probe_cold_retirement_linux.go
var mihomoHashBufferOriginalSource string

//go:embed mihomo_cold_hash_buffer_measurement_native_linux_test.go
var mihomoHashBufferCandidateSource string

func mihomoColdFileHashBufferNative(ctx context.Context, path string, buf []byte) (string, os.FileInfo, error) {
	if len(buf) != 256<<10 {
		return "", nil, ErrMihomoProbeRetirement
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 128<<20 {
		return "", nil, ErrMihomoProbeRetirement
	}
	h := sha256.New()
	for offset := int64(0); offset < before.Size(); {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		want := int(min(int64(len(buf)), before.Size()-offset))
		n, e := file.ReadAt(buf[:want], offset)
		if n != want || e != nil {
			return "", nil, ErrMihomoProbeRetirement
		}
		h.Write(buf[:n])
		offset += int64(n)
	}
	var tail [1]byte
	if n, err := file.ReadAt(tail[:], before.Size()); n != 0 || !errors.Is(err, io.EOF) {
		return "", nil, ErrMihomoProbeRetirement
	}
	after, err := file.Stat()
	named, namedErr := os.Stat(path)
	if err != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", nil, ErrMihomoProbeRetirement
	}
	return hex.EncodeToString(h.Sum(nil)), after, ctx.Err()
}

func mihomoHashBufferBody(t *testing.T, source, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			var b bytes.Buffer
			if err := format.Node(&b, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			return strings.ReplaceAll(b.String(), "\n\n", "\n")
		}
	}
	t.Fatal("missing exact function", name)
	return ""
}
func TestMihomoColdHashBufferNativeSourceParity(t *testing.T) {
	original := mihomoHashBufferBody(t, mihomoHashBufferOriginalSource, "mihomoColdFileHash")
	candidate := mihomoHashBufferBody(t, mihomoHashBufferCandidateSource, "mihomoColdFileHashBufferNative")
	allocation := "\tbuf := make([]byte, 256<<10)\n"
	guard := "\tif len(buf) != 256<<10 {\n\t\treturn \"\", nil, ErrMihomoProbeRetirement\n\t}\n"
	if strings.Count(original, allocation) != 1 || strings.Count(candidate, guard) != 1 || strings.Replace(original, allocation, "", 1) != strings.Replace(candidate, guard, "", 1) {
		t.Fatal("source changed beyond private buffer allocation")
	}
	t.Logf("COLD_HASH_BUFFER_SOURCE original_body_sha256=%x candidate_body_sha256=%x source_file_sha256=%x", sha256.Sum256([]byte(original)), sha256.Sum256([]byte(candidate)), sha256.Sum256([]byte(mihomoHashBufferOriginalSource)))
}
func mihomoHashBufferPair(ctx context.Context, path string, reuse bool) (string, int64, error) {
	var buf []byte
	if reuse {
		buf = make([]byte, 256<<10)
		defer clear(buf)
	}
	read := mihomoColdFileHash
	if reuse {
		read = func(c context.Context, p string) (string, os.FileInfo, error) {
			return mihomoColdFileHashBufferNative(c, p, buf)
		}
	}
	first, a, err := read(ctx, path)
	if err != nil {
		return "", 0, err
	}
	second, b, err := read(ctx, path)
	if err != nil {
		return "", 0, err
	}
	if first != second || !os.SameFile(a, b) || a.Size() != b.Size() {
		return "", 0, ErrMihomoProbeRetirement
	}
	return first, a.Size(), nil
}

type mihomoHashBufferCutContext struct {
	context.Context
	calls int
	cut   func(int) error
}

func (c *mihomoHashBufferCutContext) Err() error { c.calls++; return c.cut(c.calls) }
func TestMihomoColdHashBufferNativeRefusals(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		for _, cut := range []string{"mutate", "truncate", "replace", "cancel", "partial-eof", "extra-eof"} {
			t.Run(map[bool]string{false: "original", true: "private-buffer"}[reuse]+"/"+cut, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "source")
				data := bytes.Repeat([]byte{0x35}, 3*(256<<10))
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 256<<10)
				defer clear(buf)
				read := mihomoColdFileHash
				if reuse {
					read = func(c context.Context, p string) (string, os.FileInfo, error) {
						return mihomoColdFileHashBufferNative(c, p, buf)
					}
				}
				a, info, err := read(context.Background(), path)
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				switch cut {
				case "mutate":
					data[len(data)/2] ^= 1
					err = os.WriteFile(path, data, 0600)
				case "truncate":
					err = os.Truncate(path, 257)
				case "replace":
					err = os.Rename(path, path+".old")
					if err == nil {
						err = os.WriteFile(path, data, 0600)
					}
				case "cancel":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "partial-eof":
					ctx = &mihomoHashBufferCutContext{Context: ctx, cut: func(n int) error {
						if n == 2 {
							if e := os.Truncate(path, 256<<10); e != nil {
								t.Fatal(e)
							}
						}
						return nil
					}}
				case "extra-eof":
					ctx = &mihomoHashBufferCutContext{Context: ctx, cut: func(n int) error {
						if n == 2 {
							f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
							if e != nil {
								t.Fatal(e)
							}
							_, writeErr := f.Write([]byte{1})
							if e := errors.Join(writeErr, f.Close()); e != nil {
								t.Fatal(e)
							}
						}
						return nil
					}}
				}
				if err != nil {
					t.Fatal(err)
				}
				b, after, err := read(ctx, path)
				if err == nil && a == b && os.SameFile(info, after) && info.Size() == after.Size() {
					t.Fatal("changed/canceled pair accepted")
				}
			})
		}
	}
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("valid"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, (256 << 10) - 1, (256 << 10) + 1} {
		if _, _, err := mihomoColdFileHashBufferNative(context.Background(), path, make([]byte, size)); err == nil {
			t.Fatal("invalid buffer accepted", size)
		}
	}
}
func TestMihomoColdHashBufferNativePrivateConcurrentPairs(t *testing.T) {
	paths := []string{filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}
	hashes := make([]string, 2)
	for i, path := range paths {
		data := bytes.Repeat([]byte{byte(i + 1)}, (512<<10)+7)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[i] = hex.EncodeToString(sum[:])
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := range paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 4 {
				got, _, err := mihomoHashBufferPair(context.Background(), paths[i], true)
				if err != nil {
					errs <- err
					return
				}
				if got != hashes[i] {
					errs <- ErrMihomoProbeRetirement
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal("private pair interference", err)
	}
}
func TestMihomoColdHashBufferNativePairedMeasurement(t *testing.T) {
	if os.Getenv("RAZVILKA_COLD_HASH_BUFFER_MEASURE") != "1" {
		t.Skip("explicit actual executable private-buffer experiment")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	want, size, err := mihomoHashBufferPair(ctx, "/proc/self/exe", false)
	if err != nil {
		t.Fatal(err)
	}
	const samples = 2
	for pair := 0; pair < 8; pair++ {
		order := []bool{false, true}
		if pair%2 == 1 {
			order = []bool{true, false}
		}
		for _, reuse := range order {
			var memoryBefore, memoryAfter runtime.MemStats
			var cpuBefore, cpuAfter unix.Timespec
			runtime.ReadMemStats(&memoryBefore)
			if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &cpuBefore) != nil {
				t.Fatal("thread clock")
			}
			started := time.Now()
			for range samples {
				got, n, err := mihomoHashBufferPair(ctx, "/proc/self/exe", reuse)
				if err != nil || got != want || n != size {
					t.Fatal("fresh actual pair failed", err)
				}
			}
			elapsed := time.Since(started)
			if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &cpuAfter) != nil {
				t.Fatal("thread clock")
			}
			runtime.ReadMemStats(&memoryAfter)
			if memoryAfter.TotalAlloc < memoryBefore.TotalAlloc {
				t.Fatal("allocation counter regressed")
			}
			variant := "original-two-private-buffers"
			if reuse {
				variant = "one-private-buffer-cleared-after-pair"
			}
			row := map[string]any{"pair": pair, "variant": variant, "samples": samples, "image_bytes": size, "wall_ns": elapsed.Nanoseconds(), "thread_cpu_ns": cpuAfter.Nano() - cpuBefore.Nano(), "process_alloc_bytes_diagnostic": memoryAfter.TotalAlloc - memoryBefore.TotalAlloc, "scope": "two fresh complete SHA reads; not route timing; process allocation includes concurrent runtime activity"}
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("COLD_HASH_BUFFER_PAIR " + string(raw))
		}
	}
}
