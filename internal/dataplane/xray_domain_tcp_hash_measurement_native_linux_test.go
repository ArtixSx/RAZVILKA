//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type xrayHashChunkMeasurement struct {
	digest           string
	bytes, readCalls int64
}

// Test-only complete-image candidate. Larger ReadAt calls may block longer;
// <=32KiB hash ticks do not establish equivalent blocked-read cancellation.
func measureXrayHashChunk(ctx context.Context, p *xrayDomainTCPExecutable, chunk int) (out xrayHashChunkMeasurement, err error) {
	if ctx == nil {
		return out, ErrXrayDomainTCPOriginal
	}
	if p == nil || p.file == nil || p.info == nil || xraySelectedTCPFinite(ctx) != nil || p.info.Size() <= 0 || p.info.Size() > xrayDomainTCPExecutableLimit {
		return out, errors.Join(ErrXrayDomainTCPOriginal, ctx.Err())
	}
	if chunk != 32<<10 && chunk != 64<<10 && chunk != 128<<10 && chunk != 256<<10 {
		return out, ErrXrayDomainTCPOriginal
	}
	h := sha256.New()
	block := make([]byte, chunk)
	for offset := int64(0); offset < p.info.Size(); {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		want := min(int64(len(block)), p.info.Size()-offset)
		n, err := p.file.ReadAt(block[:want], offset)
		out.readCalls++
		out.bytes += int64(n)
		if int64(n) != want || err != nil && err != io.EOF {
			return out, ErrXrayDomainTCPOriginal
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		for start := 0; start < n; start += 32 << 10 {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			_, _ = h.Write(block[start:min(start+(32<<10), n)])
		}
		offset += int64(n)
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.digest = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

// Successful measurements retain both original metadata boundaries. On a hash
// refusal this diagnostic additionally runs closing metadata; production current
// short-circuits that failure path. This is not exact failure-controlflow parity.
func measureXrayHashCurrent(ctx context.Context, p *xrayDomainTCPExecutable, chunk int) (xrayHashChunkMeasurement, error) {
	if err := p.metadataCurrent(ctx); err != nil {
		return xrayHashChunkMeasurement{}, err
	}
	out, err := measureXrayHashChunk(ctx, p, chunk)
	err = errors.Join(err, p.metadataCurrent(ctx), ctx.Err())
	if err != nil || out.digest != p.sha256 {
		out.digest = ""
		return out, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return out, nil
}

func actualXrayHashMeasurement(tb testing.TB) (context.Context, *xrayDomainTCPExecutable) {
	tb.Helper()
	path := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if !filepath.IsAbs(path) {
		tb.Skip("opt-in absolute pinned native Xray fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	tb.Cleanup(cancel)
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || named.Mode().Perm()&0022 != 0 || named.Size() != 36577406 {
		tb.Fatal("actual pinned Xray size/regular-file required", err)
	}
	f, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { f.Close() })
	held, err := f.Stat()
	if err != nil || !os.SameFile(named, held) || xraySelectedTCPELFHeader(f, held.Size()) != nil {
		tb.Fatal("actual pinned held ELF required", err)
	}
	p := &xrayDomainTCPExecutable{file: f, info: held, path: path}
	p.sha256, err = p.hash(ctx)
	if err != nil || p.current(ctx) != nil {
		tb.Fatal("original complete pinned hash refused", err)
	}
	// Workflow verifies the pinned archive before installing this exact fixture.
	// This helper only holds a read-only file; it grants no process/LAN authority.
	tb.Logf("actual Xray full hash fixture bytes=%d sha256=%s; warm file measurement, not cold/router proof", held.Size(), p.sha256)
	return ctx, p
}

func TestXrayHashChunkActualParityAndCancellation(t *testing.T) {
	ctx, p := actualXrayHashMeasurement(t)
	for _, chunk := range []int{32 << 10, 64 << 10, 128 << 10, 256 << 10} {
		measured, err := measureXrayHashCurrent(ctx, p, chunk)
		if err != nil || measured.digest != p.sha256 || measured.bytes != p.info.Size() || measured.readCalls != (p.info.Size()+int64(chunk)-1)/int64(chunk) {
			t.Fatal("actual complete hash/read count differs", chunk, measured, err)
		}
		canceled, stop := context.WithCancel(ctx)
		stop()
		refused, err := measureXrayHashCurrent(canceled, p, chunk)
		if err == nil || refused.digest != "" || refused.readCalls != 0 {
			t.Fatal("canceled entry read or returned digest")
		}
		for sample := 0; sample < 3; sample++ {
			active, cancel := context.WithCancel(ctx)
			var canceledAt atomic.Int64
			joined := make(chan struct{})
			timer := time.AfterFunc(2*time.Millisecond, func() { canceledAt.Store(time.Now().UnixNano()); cancel(); close(joined) })
			refused, err := measureXrayHashCurrent(active, p, chunk)
			finished := time.Now()
			if timer.Stop() {
				cancel()
				t.Fatal("full hash completed before cancellation measurement")
			}
			<-joined
			cancel()
			latency := finished.Sub(time.Unix(0, canceledAt.Load()))
			if !errors.Is(err, context.Canceled) || refused.digest != "" || latency < 0 || latency > 2*time.Second {
				t.Fatal("cancel completion not joined/refused", chunk, latency, err)
			}
			t.Logf("actual_hash_cancel chunk=%d sample=%d post_cancel_ns=%d read_at_calls=%d bytes=%d; blocked-read granularity is measured, not assumed equivalent", chunk, sample, latency.Nanoseconds(), refused.readCalls, refused.bytes)
		}
	}
}

type xrayHashLateCancel struct {
	context.Context
	ticks, at int
}

func (c *xrayHashLateCancel) Err() error {
	c.ticks++
	if c.ticks >= c.at {
		return context.Canceled
	}
	return nil
}

func TestXrayHashChunkRefusesPartialAndChangedFiles(t *testing.T) {
	for _, chunk := range []int{32 << 10, 64 << 10, 128 << 10, 256 << 10} {
		t.Run(fmt.Sprint(chunk), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "held-image")
			data := make([]byte, (256<<10)+1)
			for i := range data {
				data[i] = byte(i)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			p := &xrayDomainTCPExecutable{file: f, info: info, path: path}
			p.sha256, err = p.hash(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got, err := measureXrayHashCurrent(ctx, p, chunk)
			if err != nil || got.digest != p.sha256 {
				t.Fatal("unmodified image differs", err)
			}
			late := &xrayHashLateCancel{Context: ctx, at: 8}
			got, err = measureXrayHashCurrent(late, p, chunk)
			if !errors.Is(err, context.Canceled) || got.digest != "" || got.readCalls == 0 || got.bytes == 0 {
				t.Fatal("partial-read cancellation missing or digest escaped", got, err)
			}
			if _, err = f.WriteAt([]byte{0xff}, 0); err != nil {
				t.Fatal(err)
			}
			if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			got, err = measureXrayHashCurrent(ctx, p, chunk)
			if err == nil || got.digest != "" {
				t.Fatal("changed full bytes accepted")
			}
			if err = f.Truncate(17); err != nil {
				t.Fatal(err)
			}
			got, err = measureXrayHashChunk(ctx, p, chunk)
			if err == nil || got.digest != "" {
				t.Fatal("short read accepted")
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			got, err = measureXrayHashChunk(ctx, p, chunk)
			if err == nil || got.digest != "" {
				t.Fatal("closed descriptor read accepted")
			}
		})
	}
}

func BenchmarkXrayCompleteHashChunks(b *testing.B) {
	ctx, p := actualXrayHashMeasurement(b)
	b.Run("original32", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(p.info.Size())
		for range b.N {
			if err := p.current(ctx); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64((p.info.Size()+(32<<10)-1)/(32<<10)), "read-at-calls/op")
	})
	for _, chunk := range []int{32 << 10, 64 << 10, 128 << 10, 256 << 10} {
		b.Run(fmt.Sprint(chunk), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(p.info.Size())
			var calls int64
			for range b.N {
				out, err := measureXrayHashCurrent(ctx, p, chunk)
				if err != nil {
					b.Fatal(err)
				}
				calls += out.readCalls
			}
			b.ReportMetric(float64(calls)/float64(b.N), "read-at-calls/op")
		})
	}
}
