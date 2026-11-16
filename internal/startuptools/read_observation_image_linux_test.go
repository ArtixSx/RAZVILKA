//go:build linux && (amd64 || arm64)

package startuptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func toolImageFixture(t *testing.T) (context.Context, context.CancelFunc, *heldReview, *heldImage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	root := t.TempDir()
	path := filepath.Join(root, "image")
	data := bytes.Repeat([]byte{0x63}, 3*(32<<10)+19)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	i := &heldImage{path: path, file: f, info: info, hash: sha256.Sum256(data)}
	r := &heldReview{profile: profile{extension: root}, images: map[string]*heldImage{path: i}, nodes: map[string]heldNode{root: {path: root, info: dir}, path: {path: path, info: info}}, absent: map[string]bool{filepath.Join(root, "missing"): true}, extensions: []string{"image"}, bytes: info.Size()}
	return ctx, cancel, r, i
}

func TestToolObservationImagePairRefusals(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected graph comparisons require root; pure image tests run separately")
	}
	for _, mode := range []string{"clean", "first-byte", "last-byte", "truncate", "append", "replacement", "digest", "graph", "extension", "negative-path", "cancel", "closed-fd", "foreign-context", "repeat", "copied", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel, r, image := toolImageFixture(t)
			var slot toolObservationImageScratch
			s, err := borrowToolObservationImage(ctx, r, &slot)
			if err != nil || s == nil {
				t.Fatal("image unavailable", err)
			}
			defer s.release()
			if err := s.current(ctx, ctx, r); err != nil {
				t.Fatal("opening", err)
			}
			if s.phase != 1 || sha256.Sum256(s.entries[image].data) != image.hash {
				t.Fatal("opening bytes are not original SHA")
			}
			parent := ctx
			switch mode {
			case "first-byte", "last-byte":
				f, err := os.OpenFile(image.path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				offset := int64(0)
				if mode == "last-byte" {
					offset = image.info.Size() - 1
				}
				_, err = f.WriteAt([]byte{0x64}, offset)
				if err := errors.Join(err, f.Close(), os.Chtimes(image.path, image.info.ModTime(), image.info.ModTime())); err != nil {
					t.Fatal(err)
				}
			case "truncate":
				if err := os.Truncate(image.path, 17); err != nil {
					t.Fatal(err)
				}
			case "append":
				if err := os.Truncate(image.path, image.info.Size()+1); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err := os.Rename(image.path, image.path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(image.path, s.entries[image].data, 0600); err != nil {
					t.Fatal(err)
				}
			case "digest":
				image.hash[0] ^= 1
			case "graph":
				copied := *image
				r.images[image.path] = &copied
			case "extension", "negative-path":
				name := "extra"
				if mode == "negative-path" {
					name = "missing"
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(image.path), name), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "closed-fd":
				if err := image.file.Close(); err != nil {
					t.Fatal(err)
				}
			case "foreign-context":
				parent = context.WithValue(ctx, struct{}{}, true)
			case "copied":
				copy := *s
				if copy.current(ctx, ctx, r) == nil {
					t.Fatal("copied private image accepted")
				}
				copy.release()
				if !slot.busy.Load() {
					t.Fatal("copy released original storage")
				}
			case "panic":
				func() { defer func() { _ = recover() }(); defer s.release(); panic("reader failed") }()
			}
			err = s.current(parent, ctx, r)
			want := mode == "clean" || mode == "repeat" || mode == "copied"
			if (err == nil) != want {
				t.Fatal("closing result", mode, err)
			}
			if mode == "repeat" && s.current(ctx, ctx, r) == nil {
				t.Fatal("completed pair reused")
			}
			s.release()
			if slot.busy.Load() || !bytes.Equal(slot.data, make([]byte, len(slot.data))) || s.entries != nil {
				t.Fatal("storage not revoked and cleared")
			}
		})
	}
}

func TestToolObservationImageFixedSlotFallback(t *testing.T) {
	ctx, _, r, original := toolImageFixture(t)
	var slot toolObservationImageScratch
	if image, err := borrowToolObservationImage(toolImageNoncomparableContext{Context: ctx}, r, &slot); image != nil || err != nil || slot.data != nil {
		t.Fatal("optional image narrowed original context ABI", err)
	}
	held, err := borrowToolObservationImage(ctx, r, &slot)
	if err != nil || held == nil {
		t.Fatal(err)
	}
	defer held.release()
	done := make(chan error, 1)
	go func() {
		other, err := borrowToolObservationImage(ctx, r, &slot)
		if other != nil {
			other.release()
			err = errors.New("busy storage reused")
		}
		done <- err
	}()
	if err := <-done; err != nil || !slot.busy.Load() {
		t.Fatal("busy fallback", err)
	}
	for range 2 {
		got, err := hashImage(ctx, original.file, original.info.Size())
		if err != nil || got != original.hash {
			t.Fatal("ordinary SHA fallback", err)
		}
	}
	held.release()
	var small toolObservationImageScratch
	small.data = make([]byte, 1)
	if image, err := borrowToolObservationImage(ctx, r, &small); image != nil || err != nil || len(small.data) != 1 || small.busy.Load() {
		t.Fatal("small slot resized/refused", err)
	}
	r.bytes = toolObservationImageLimit + 1
	var empty toolObservationImageScratch
	if image, err := borrowToolObservationImage(ctx, r, &empty); image != nil || err != nil || empty.data != nil {
		t.Fatal("oversize must retain ordinary path", err)
	}
}

type toolImageNoncomparableContext struct {
	context.Context
	noncomparable []byte
}

type toolImageReadTicks struct {
	context.Context
	calls int
}

func (c *toolImageReadTicks) Err() error { c.calls++; return c.Context.Err() }

func TestToolObservationImageReadsAfterMismatch(t *testing.T) {
	ctx, _, r, image := toolImageFixture(t)
	var slot toolObservationImageScratch
	s, err := borrowToolObservationImage(ctx, r, &slot)
	if err != nil || s == nil {
		t.Fatal(err)
	}
	defer s.release()
	s.reading = true
	if got, err := s.read(ctx, image, image.info.Size()); err != nil || got != image.hash {
		t.Fatal("actual opening SHA byte loop", err)
	}
	s.reading, s.phase, s.entries[image].read = false, 1, false
	f, err := os.OpenFile(image.path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte{0x64}, 0)
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	readctx := &toolImageReadTicks{Context: ctx}
	s.reading = true // Exercise the actual byte loop, independent of metadata refusal.
	_, err = s.read(readctx, image, image.info.Size())
	s.reading = false
	chunks := int((image.info.Size() + (32 << 10) - 1) / (32 << 10))
	if err == nil || readctx.calls < chunks+1 {
		t.Fatal("mismatch skipped remaining full byte range", err, readctx.calls, chunks)
	}
}
