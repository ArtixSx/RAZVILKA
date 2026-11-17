//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
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

// Private test data only. This does not solve production resource lifetime,
// concurrent close, revocation or the extra full-image memory budget.
type xrayPrivateImageMeasurement struct {
	source *xrayDomainTCPExecutable
	image  []byte
	digest string
}

func captureXrayPrivateImageMeasurement(ctx context.Context, p *xrayDomainTCPExecutable) (*xrayPrivateImageMeasurement, error) {
	if ctx == nil || p == nil || p.info == nil || p.info.Size() <= 0 || p.info.Size() > xrayDomainTCPExecutableLimit {
		return nil, ErrXrayDomainTCPOriginal
	}
	if err := p.metadataCurrent(ctx); err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	image := make([]byte, p.info.Size())
	keep := false
	defer func() {
		if !keep {
			clear(image)
		}
	}()
	h := sha256.New()
	var readErr error
	for offset := int64(0); offset < p.info.Size(); {
		if readErr = ctx.Err(); readErr != nil {
			break
		}
		want := min(int64(32<<10), p.info.Size()-offset)
		n, err := p.file.ReadAt(image[offset:offset+want], offset)
		if int64(n) != want || err != nil && err != io.EOF {
			readErr = errors.Join(ErrXrayDomainTCPOriginal, err)
			break
		}
		if readErr = ctx.Err(); readErr != nil {
			break
		}
		_, _ = h.Write(image[offset : offset+int64(n)])
		offset += int64(n)
	}
	closing := errors.Join(p.metadataCurrent(ctx), ctx.Err())
	if readErr != nil || closing != nil || hex.EncodeToString(h.Sum(nil)) != p.sha256 {
		return nil, errors.Join(ErrXrayDomainTCPOriginal, readErr, closing)
	}
	keep = true
	return &xrayPrivateImageMeasurement{source: p, image: image, digest: p.sha256}, nil
}

// Every current byte is read again. A mismatch does not stop the remaining
// reads. Like the chunk diagnostic, failure paths also run closing metadata;
// success has the original metadata boundaries, not a production authority.
func compareXrayPrivateImageMeasurement(ctx context.Context, p *xrayDomainTCPExecutable, image *xrayPrivateImageMeasurement) (out xrayHashChunkMeasurement, resultErr error) {
	if ctx == nil || p == nil || p.info == nil || image == nil || image.source != p || image.digest != p.sha256 || int64(len(image.image)) != p.info.Size() || p.info.Size() <= 0 || p.info.Size() > xrayDomainTCPExecutableLimit {
		return out, ErrXrayDomainTCPOriginal
	}
	if err := p.metadataCurrent(ctx); err != nil {
		return out, errors.Join(err, ctx.Err())
	}
	defer func() {
		resultErr = errors.Join(resultErr, p.metadataCurrent(ctx), ctx.Err())
		if resultErr != nil {
			out.digest = ""
		}
	}()
	var block [32 << 10]byte
	equal := true
	for offset := int64(0); offset < p.info.Size(); {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		want := min(int64(len(block)), p.info.Size()-offset)
		n, err := p.file.ReadAt(block[:want], offset)
		out.readCalls++
		out.bytes += int64(n)
		if int64(n) != want || err != nil && err != io.EOF {
			return out, errors.Join(ErrXrayDomainTCPOriginal, err)
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !bytes.Equal(block[:n], image.image[offset:offset+int64(n)]) {
			equal = false
		}
		offset += int64(n)
	}
	if !equal {
		return out, ErrXrayDomainTCPOriginal
	}
	out.digest = p.sha256 // Label of authenticated equal bytes, not a new hash.
	return out, nil
}

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

func TestXrayHashChunkPrivateImageActualParity(t *testing.T) {
	ctx, p := actualXrayHashMeasurement(t)
	start := time.Now()
	image, err := captureXrayPrivateImageMeasurement(ctx, p)
	if err != nil {
		t.Fatal("first fresh image/SHA capture", err)
	}
	defer clear(image.image)
	t.Logf("actual_private_image_capture elapsed_ns=%d retained_bytes=%d; first capture/authentication separate from repeated reads", time.Since(start).Nanoseconds(), len(image.image))
	out, err := compareXrayPrivateImageMeasurement(ctx, p, image)
	if err != nil || out.digest != p.sha256 || out.bytes != p.info.Size() || out.readCalls != (p.info.Size()+(32<<10)-1)/(32<<10) || p.current(ctx) != nil {
		t.Fatal("complete original hash/byte comparison differs", out, err)
	}
	for sample := 0; sample < 3; sample++ {
		active, cancel := context.WithCancel(ctx)
		var canceledAt atomic.Int64
		joined := make(chan struct{})
		timer := time.AfterFunc(100*time.Microsecond, func() { canceledAt.Store(time.Now().UnixNano()); cancel(); close(joined) })
		out, err := compareXrayPrivateImageMeasurement(active, p, image)
		finished := time.Now()
		if timer.Stop() {
			cancel()
			t.Fatal("full comparison completed before cancellation measurement")
		}
		<-joined
		cancel()
		latency := finished.Sub(time.Unix(0, canceledAt.Load()))
		if !errors.Is(err, context.Canceled) || out.digest != "" || latency < 0 || latency > 2*time.Second {
			t.Fatal("private image comparison cancellation not joined/refused", out, latency, err)
		}
		t.Logf("actual_private_image_cancel sample=%d post_cancel_ns=%d read_at_calls=%d bytes=%d; same32KiB read granularity, not production lifecycle proof", sample, latency.Nanoseconds(), out.readCalls, out.bytes)
	}
}

type xrayImageReadFault struct {
	context.Context
	ticks, at int
	change    func() error
	err       error
}

func (c *xrayImageReadFault) Err() error {
	c.ticks++
	if c.ticks == c.at {
		c.err = c.change()
	}
	return c.Context.Err()
}

func TestXrayHashChunkPrivateImageRefusals(t *testing.T) {
	for _, mutation := range []string{"same-size", "replacement", "truncate", "closed", "late-short-read", "late-read-error", "closing-replacement"} {
		t.Run(mutation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "held-image")
			data := bytes.Repeat([]byte{0x5a}, (256<<10)+1)
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
			image, err := captureXrayPrivateImageMeasurement(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(image.image)
			if out, err := compareXrayPrivateImageMeasurement(ctx, p, image); err != nil || out.bytes != info.Size() {
				t.Fatal("fresh full image rejected", out, err)
			}
			canceled, stop := context.WithCancel(ctx)
			stop()
			if refused, err := captureXrayPrivateImageMeasurement(canceled, p); err == nil || refused != nil {
				t.Fatal("canceled capture published data")
			}
			if out, err := compareXrayPrivateImageMeasurement(canceled, p, image); !errors.Is(err, context.Canceled) || out.bytes != 0 || out.digest != "" {
				t.Fatal("canceled entry read/succeeded", out, err)
			}
			late := &xrayHashLateCancel{Context: ctx, at: 8}
			if out, err := compareXrayPrivateImageMeasurement(late, p, image); !errors.Is(err, context.Canceled) || out.bytes == 0 || out.bytes == info.Size() || out.digest != "" {
				t.Fatal("partial read cancellation missing", out, err)
			}
			originalSHA := p.sha256
			p.sha256 = "unauthenticated"
			if refused, err := captureXrayPrivateImageMeasurement(ctx, p); err == nil || refused != nil {
				t.Fatal("wrong SHA published private bytes")
			}
			if out, err := compareXrayPrivateImageMeasurement(ctx, p, image); err == nil || out.digest != "" || out.readCalls != 0 {
				t.Fatal("changed digest binding accepted private image", out, err)
			}
			p.sha256 = originalSHA
			foreign := *p
			if _, err := compareXrayPrivateImageMeasurement(ctx, &foreign, image); err == nil {
				t.Fatal("foreign executable accepted private image")
			}
			compareCtx := ctx
			var fault *xrayImageReadFault
			switch mutation {
			case "same-size":
				_, err = f.WriteAt([]byte{0xff}, 0)
				if err == nil {
					err = os.Chtimes(path, info.ModTime(), info.ModTime())
				}
			case "replacement":
				err = os.WriteFile(path+".replacement", data, 0600)
				if err == nil {
					err = os.Rename(path+".replacement", path)
				}
			case "truncate":
				err = f.Truncate(17)
			case "closed":
				err = f.Close()
			case "late-short-read", "late-read-error":
				// Two opening metadata Err calls precede the first read tick.
				fault = &xrayImageReadFault{Context: ctx, at: 3, change: func() error {
					if mutation == "late-short-read" {
						return f.Truncate(17)
					}
					return f.Close()
				}}
				compareCtx = fault
			case "closing-replacement":
				err = os.WriteFile(path+".replacement", data, 0600)
				// Opening metadata + two Err calls per complete32KiB read.
				fault = &xrayImageReadFault{Context: ctx, at: 3 + 2*int((info.Size()+(32<<10)-1)/(32<<10)), change: func() error {
					return os.Rename(path+".replacement", path)
				}}
				compareCtx = fault
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := compareXrayPrivateImageMeasurement(compareCtx, p, image)
			if err == nil || out.digest != "" || p.current(ctx) == nil {
				t.Fatal("original/full comparison refusal parity lost", out, err)
			}
			if mutation == "same-size" && (out.bytes != info.Size() || out.readCalls != (info.Size()+(32<<10)-1)/(32<<10)) {
				t.Fatal("first-byte mismatch skipped remaining full-image reads", out)
			}
			if fault != nil && (fault.ticks < fault.at || fault.err != nil || out.readCalls == 0) {
				t.Fatal("in-read/closing fault was not actually reached", out, fault.err)
			}
			if mutation == "closing-replacement" && out.bytes != info.Size() {
				t.Fatal("replacement did not occur after complete image comparison", out)
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
	b.Run("private_capture_sha_clear", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(p.info.Size())
		for range b.N {
			image, err := captureXrayPrivateImageMeasurement(ctx, p)
			if err != nil || int64(len(image.image)) != p.info.Size() {
				b.Fatal("private capture refused", err)
			}
			// Include clearing in this separate capture cost. This does not
			// imply immediate GC reclamation or a production lifetime policy.
			clear(image.image)
		}
		b.ReportMetric(float64(p.info.Size()), "retained-bytes/image")
	})
	image, err := captureXrayPrivateImageMeasurement(ctx, p)
	if err != nil {
		b.Fatal("private repeat fixture capture refused", err)
	}
	defer clear(image.image)
	b.Run("private_repeat_compare", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(p.info.Size())
		var calls int64
		for range b.N {
			out, err := compareXrayPrivateImageMeasurement(ctx, p, image)
			if err != nil {
				b.Fatal(err)
			}
			calls += out.readCalls
		}
		b.ReportMetric(float64(calls)/float64(b.N), "read-at-calls/op")
		b.ReportMetric(float64(len(image.image)), "retained-bytes/image")
	})
}
