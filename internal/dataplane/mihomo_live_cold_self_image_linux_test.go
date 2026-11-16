//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mihomoSelfImageFixture(t *testing.T) (context.Context, context.CancelFunc, string, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	path := filepath.Join(t.TempDir(), "image")
	data := bytes.Repeat([]byte("original binary fixture\n"), 40000)
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	return ctx, cancel, path, data
}

func TestMihomoColdSelfImagePairAndRefusals(t *testing.T) {
	for _, mode := range []string{"clean", "same-inode-mutation", "grow", "shrink", "replacement", "cancel", "foreign-context", "copied", "repeat", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel, path, data := mihomoSelfImageFixture(t)
			var scratch xrayDomainTCPImageScratch
			image, err := borrowMihomoColdSelfImage(ctx, path, &scratch)
			if err != nil || image == nil {
				t.Fatal("opening storage unavailable", err)
			}
			t.Cleanup(image.release)
			opening, original, err := image.read(ctx)
			want, wantInfo, wantErr := mihomoColdFileHash(ctx, path)
			if err != nil || wantErr != nil || opening != want || !os.SameFile(original, wantInfo) || !bytes.Equal(image.lease.data, data) {
				t.Fatal("opening differs from complete original SHA", err, wantErr)
			}
			if mode == "panic" {
				func() {
					defer func() { _ = recover() }()
					defer image.release()
					panic("synchronous observer failure")
				}()
			} else {
				readContext := ctx
				switch mode {
				case "same-inode-mutation":
					file, err := os.OpenFile(path, os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = file.WriteAt([]byte{0xff}, 0)
					if err := errors.Join(err, file.Close(), os.Chtimes(path, original.ModTime(), original.ModTime())); err != nil {
						t.Fatal(err)
					}
				case "grow":
					if err := os.Truncate(path, int64(len(data)+1)); err != nil {
						t.Fatal(err)
					}
				case "shrink":
					if err := os.Truncate(path, int64(len(data)-1)); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					if err := os.WriteFile(path+"-foreign", data, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+"-foreign", path); err != nil {
						t.Fatal(err)
					}
				case "cancel":
					cancel()
				case "foreign-context":
					readContext = context.WithValue(ctx, struct{}{}, true)
				case "copied":
					copied := &mihomoColdSelfImage{self: image, ctx: ctx, path: path, lease: image.lease}
					if _, _, err := copied.read(ctx); err == nil {
						t.Fatal("copied image accepted")
					}
					copied.release()
					if image.lease.closed.Load() || !scratch.busy.Load() {
						t.Fatal("copy revoked original storage")
					}
				}
				closing, closingInfo, err := image.read(readContext)
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("original cancellation cause lost", err)
				}
				// Preserve the caller's original inode+size comparison too: equal
				// bytes in a new inode must not become the original self-image.
				accepted := err == nil && closing == opening && os.SameFile(original, closingInfo) && original.Size() == closingInfo.Size()
				if accepted != (mode == "clean" || mode == "copied" || mode == "repeat") {
					t.Fatal("closing byte/identity refusal changed", mode, err)
				}
				if mode == "repeat" {
					if _, _, err := image.read(ctx); err == nil {
						t.Fatal("consumed comparison reused")
					}
				}
				image.release()
			}
			if scratch.busy.Load() || !image.lease.closed.Load() || !bytes.Equal(scratch.data, make([]byte, len(scratch.data))) {
				t.Fatal("private storage retained after completion/refusal/panic")
			}
		})
	}
}

func TestMihomoColdSelfImageForcedFallback(t *testing.T) {
	for _, mode := range []string{"occupied", "fixed-small", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			ctx, _, path, data := mihomoSelfImageFixture(t)
			var scratch xrayDomainTCPImageScratch
			var held *xrayDomainTCPImageLease
			switch mode {
			case "occupied":
				held = scratch.borrow(1)
				t.Cleanup(held.release)
			case "fixed-small":
				small := scratch.borrow(1)
				small.release()
			case "oversize":
				if err := os.Truncate(path, xrayDomainTCPImageScratchLimit+1); err != nil {
					t.Fatal(err)
				}
			}
			image, err := borrowMihomoColdSelfImage(ctx, path, &scratch)
			if err != nil || image != nil {
				t.Fatal("storage limit did not choose original path", err)
			}
			if mode == "occupied" && (!scratch.busy.Load() || held.closed.Load()) || mode == "fixed-small" && len(scratch.data) != 1 || mode == "oversize" && scratch.data != nil {
				t.Fatal("fallback changed another lease or resized storage")
			}
			if mode != "oversize" {
				first, a, err := mihomoColdFileHash(ctx, path)
				second, b, secondErr := mihomoColdFileHash(ctx, path)
				if err != nil || secondErr != nil || first != nodeDefaultSourceMaterialHash(data) || second != first || !os.SameFile(a, b) {
					t.Fatal("original fallback pair unavailable", err, secondErr)
				}
			}
		})
	}
}

type mihomoSelfImagePartialCancel struct {
	context.Context
	calls, stop int
}

func (c *mihomoSelfImagePartialCancel) Err() error {
	c.calls++
	if c.stop > 0 && c.calls >= c.stop {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestMihomoColdSelfImagePartialOpeningNeverAuthenticates(t *testing.T) {
	base, _, path, data := mihomoSelfImageFixture(t)
	ctx := &mihomoSelfImagePartialCancel{Context: base}
	var scratch xrayDomainTCPImageScratch
	image, err := borrowMihomoColdSelfImage(ctx, path, &scratch)
	if err != nil || image == nil {
		t.Fatal("actual opening storage", err)
	}
	defer image.release()
	ctx.stop = ctx.calls + 3 // Entry, first actual chunk, cancellation at next chunk.
	if hash, _, err := image.read(ctx); !errors.Is(err, context.Canceled) || hash != "" || image.phase.Load() != 4 {
		t.Fatal("partial original read authenticated an image", err)
	}
	const chunk = 256 << 10
	if !bytes.Equal(image.lease.data[:chunk], data[:chunk]) || !bytes.Equal(image.lease.data[chunk:], make([]byte, len(data)-chunk)) {
		t.Fatal("test did not interrupt after exactly one actual original chunk")
	}
	// Even making the test context live again cannot reuse the partial image.
	ctx.stop = 0
	if _, _, err := image.read(ctx); err == nil {
		t.Fatal("failed opening reused after cancellation")
	}
	image.release()
	if scratch.busy.Load() || !bytes.Equal(scratch.data, make([]byte, len(scratch.data))) {
		t.Fatal("partial opening retained private bytes or storage")
	}
}

type mihomoColdSelfReadTicks struct {
	context.Context
	ticks int
}

func (c *mihomoColdSelfReadTicks) Err() error {
	c.ticks++
	return c.Context.Err()
}

func TestMihomoColdSelfImageReadsPastFirstMismatch(t *testing.T) {
	parent, _, path, data := mihomoSelfImageFixture(t)
	ctx := &mihomoColdSelfReadTicks{Context: parent}
	var scratch xrayDomainTCPImageScratch
	image, err := borrowMihomoColdSelfImage(ctx, path, &scratch)
	if err != nil || image == nil {
		t.Fatal(err)
	}
	defer image.release()
	if _, _, err := image.read(ctx); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteAt([]byte{0xff}, 0)
	if err := errors.Join(err, file.Close()); err != nil {
		t.Fatal(err)
	}
	ctx.ticks = 0
	if _, _, err := image.read(ctx); err == nil {
		t.Fatal("modified first byte accepted")
	}
	chunks := (len(data) + (256 << 10) - 1) / (256 << 10)
	if ctx.ticks < 1+chunks {
		t.Fatal("mismatch shortened the complete fresh closing read", ctx.ticks, chunks)
	}
}
