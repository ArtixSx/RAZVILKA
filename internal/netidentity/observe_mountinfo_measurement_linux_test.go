//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Measurement only. The production reader and its 4096-byte chunk are unchanged.
// Preserve its ORIGINAL call bound even when testing larger read requests.
func measureMountinfoRead(ctx context.Context, limit, chunkSize int, read func([]byte) (int, error)) ([]byte, int, bool) {
	if ctx == nil || limit < 1 || limit > maxMountBytes || (chunkSize != 4096 && chunkSize != 16<<10 && chunkSize != 32<<10) {
		return nil, 0, false
	}
	data := make([]byte, 0)
	buffer := make([]byte, min(chunkSize, limit+1))
	reads := 0
	for calls := 0; calls < limit/4096+3; calls++ {
		need := limit + 1 - len(data)
		if ctx.Err() != nil || need <= 0 {
			return nil, reads, false
		}
		chunk := buffer[:min(need, len(buffer))]
		reads++
		n, err := read(chunk)
		// Measurement refusal is stricter at this boundary: do not report a
		// successful sample if cancellation happened inside the actual read.
		if ctx.Err() != nil || err != nil || n < 0 || n > len(chunk) {
			return nil, reads, false
		}
		if n == 0 {
			return data, reads, true
		}
		data = append(data, chunk[:n]...)
		if len(data) > limit {
			return nil, reads, false
		}
	}
	return nil, reads, false
}

func TestProcMountinfoMeasurementReadBounds(t *testing.T) {
	for _, chunk := range []int{4096, 16 << 10, 32 << 10} {
		for _, size := range []int{0, 1, 4095, 4096, 4097, 32768, maxMountBytes, maxMountBytes + 1} {
			t.Run(fmt.Sprintf("chunk%d/bytes%d", chunk, size), func(t *testing.T) {
				want := bytes.Repeat([]byte{'x'}, size)
				offset := 0
				data, calls, ok := measureMountinfoRead(t.Context(), maxMountBytes, chunk, func(p []byte) (int, error) {
					n := copy(p, want[offset:])
					offset += n
					return n, nil
				})
				if ok != (size <= maxMountBytes) || ok && !bytes.Equal(data, want) || !ok && data != nil || calls > maxMountBytes/4096+3 {
					t.Fatal("changed byte/EOF/call bounds", len(data), calls, ok)
				}
			})
		}
		for _, kind := range []string{"canceled-entry", "canceled-between-reads", "canceled-at-eof", "error", "invalid-count", "short-read-call-bound"} {
			t.Run(fmt.Sprintf("chunk%d/%s", chunk, kind), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if kind == "canceled-entry" {
					cancel()
				}
				data, calls, ok := measureMountinfoRead(ctx, maxMountBytes, chunk, func(p []byte) (int, error) {
					switch kind {
					case "canceled-entry":
						t.Fatal("read after entry cancellation")
					case "canceled-between-reads":
						cancel()
					case "canceled-at-eof":
						cancel()
						return 0, nil
					case "error":
						return 0, syscall.EIO
					case "invalid-count":
						return len(p) + 1, nil
					}
					p[0] = 'x'
					return 1, nil
				})
				if ok || data != nil || kind == "canceled-entry" && calls != 0 || kind == "canceled-between-reads" && calls != 1 || kind == "short-read-call-bound" && calls != maxMountBytes/4096+3 {
					t.Fatal("failure or exact short-read bound escaped", calls, ok)
				}
			})
		}
	}
}

// This deliberately duplicates only the production opened-FD admission checks;
// none is weakened to make a larger read request look faster.
func measureMountinfoFile(a *audit, parent int, rootMount uint64, chunk int) ([]byte, int, bool) {
	if a.ctx.Err() != nil {
		return nil, 0, false
	}
	fd, err := syscall.Openat(parent, "mountinfo", fileFlags, 0)
	if err != nil {
		return nil, 0, false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &st) != nil || syscall.Fstatfs(fd, &fs) != nil ||
		st.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Type != procMagic ||
		st.Dev != a.root.stat.Dev || fs.Fsid != a.root.fs.Fsid {
		return nil, 0, false
	}
	id, ok := a.mountID(fd)
	if !ok || id != rootMount {
		return nil, 0, false
	}
	return measureMountinfoRead(a.ctx, maxMountBytes, chunk, func(p []byte) (int, error) { return syscall.Read(fd, p) })
}

func BenchmarkProcMountinfoReadChunks(b *testing.B) {
	// Actual proc bytes on this runner; neither a cold-cache experiment nor a
	// full provider/router/LAN benchmark. Every pair obtains two fresh opens.
	for _, chunk := range []int{4096, 16 << 10, 32 << 10} {
		b.Run(fmt.Sprintf("bytes%d", chunk), func(b *testing.B) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			a := &audit{ctx: ctx, fdinfo: -1}
			defer a.close()
			fd, err := syscall.Open("/proc", dirFlags, 0)
			if err != nil {
				b.Fatal(err)
			}
			root, ok := a.take(fd, true, false)
			if !ok || root.stat.Ino != 1 {
				b.Fatal("original proc root unavailable")
			}
			a.root = root
			pidName, tidName := strconv.Itoa(os.Getpid()), strconv.Itoa(syscall.Gettid())
			pid, ok := a.openDir(root.fd, pidName)
			if !ok {
				b.Fatal("original process directory unavailable")
			}
			a.fdinfo, ok = a.openDir(pid, "fdinfo")
			if !ok {
				b.Fatal("original fdinfo unavailable")
			}
			tasks, ok := a.openDir(pid, "task")
			if !ok {
				b.Fatal("original task directory unavailable")
			}
			tid, ok := a.openDir(tasks, tidName)
			if !ok {
				b.Fatal("original current thread directory unavailable")
			}
			rootMount, ok := a.mountID(root.fd)
			paths := []string{"/proc/self", "/proc/thread-self", "/proc/" + pidName,
				"/proc/" + pidName + "/fdinfo", "/proc/" + pidName + "/task/" + tidName + "/mountinfo"}
			if !ok || !a.stable() || !a.mountsMatch(rootMount) {
				b.Fatal("opening original proc custody")
			}
			control, ok := a.readFile(tid, "mountinfo", maxMountBytes, rootMount)
			if !ok || !mountLayoutOK(control, rootMount, paths) {
				b.Fatal("production 4096 reader/parser refused")
			}
			actual, _, ok := measureMountinfoFile(a, tid, rootMount, chunk)
			if !ok || !bytes.Equal(control, actual) {
				b.Fatal("measurement reader differs from actual production reader")
			}
			var reads, totalBytes int64
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				before, firstReads, ok := measureMountinfoFile(a, tid, rootMount, chunk)
				if !ok || !mountLayoutOK(before, rootMount, paths) {
					b.Fatal("complete opening mount image refused")
				}
				after, lastReads, ok := measureMountinfoFile(a, tid, rootMount, chunk)
				if !ok || !bytes.Equal(before, after) || !mountLayoutOK(after, rootMount, paths) || !a.stable() || !a.mountsMatch(rootMount) {
					b.Fatal("complete independent closing image/custody refused")
				}
				reads += int64(firstReads + lastReads)
				totalBytes += int64(len(before) + len(after))
			}
			b.StopTimer()
			b.ReportMetric(float64(reads)/float64(b.N), "read-syscalls/op")
			b.ReportMetric(float64(totalBytes)/float64(b.N), "read-bytes/op")
		})
	}
}
