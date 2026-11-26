//go:build linux && (amd64 || arm64)

package netidentity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Actual retained regular FD and bytes; ONLY Fstatfs is an explicit model.
// This cannot establish native SquashFS, executable or namespace acceptance.
func immutableImageModel(t *testing.T, immutable bool) (*systemImages, *protectedImage, *syscall.Statfs_t) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected image root-owner model")
	}
	path := filepath.Join(t.TempDir(), "image")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(bytes.Repeat([]byte("original-image!!"), 128<<10)); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := imageHash(t.Context(), file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	fs := &syscall.Statfs_t{Type: 0x73717368, Flags: 0x1021, Bsize: 4096, Blocks: 512, Files: 11}
	image := &protectedImage{file: file, info: info, nodes: []protectedNode{{path: path, info: info}}, hash: hash}
	if immutable {
		frozen := *fs
		image.immutableFS = &frozen
	}
	s := &systemImages{files: []*protectedImage{image}, readFilesystem: func(f *os.File) (syscall.Statfs_t, error) {
		if f != file {
			return syscall.Statfs_t{}, ErrUnknown
		}
		return *fs, nil
	}}
	return s, image, fs
}

func TestImmutableHeldImageSkipsOnlyRedundantContentReads(t *testing.T) {
	for _, immutable := range []bool{false, true} {
		s, image, _ := immutableImageModel(t, immutable)
		before, err := nativeImageReadChars()
		if err != nil {
			t.Fatal(err)
		}
		if !s.unchanged(t.Context()) || !s.unchanged(t.Context()) {
			t.Fatal("unchanged image refused")
		}
		after, err := nativeImageReadChars()
		if err != nil || after < before {
			t.Fatal("process read counter unavailable", err)
		}
		if immutable && after-before > 64<<10 {
			t.Fatal("immutable closing checks reread content", after-before)
		}
		if !immutable && after-before < uint64(2*image.info.Size()) {
			t.Fatal("mutable closing checks skipped full hash", after-before)
		}
	}
}

func TestImmutableHeldImageRefusesMetadataPathAndFilesystemChanges(t *testing.T) {
	for _, kind := range []string{"replacement", "symlink", "mode", "owner", "size", "mtime", "fs-type", "fs-readonly", "fs-tuple", "fs-error", "closing-fs", "closing-content", "closed", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			s, image, fs := immutableImageModel(t, true)
			path := image.file.Name()
			ctx := t.Context()
			switch kind {
			case "replacement", "symlink":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if kind == "replacement" {
					raw, err := os.ReadFile(path + ".old")
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := image.file.Chmod(0700); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if err := image.file.Chown(101, 101); err != nil {
					t.Fatal(err)
				}
			case "size":
				if err := image.file.Truncate(1); err != nil {
					t.Fatal(err)
				}
			case "mtime":
				if err := os.Chtimes(path, time.Unix(10, 0), time.Unix(10, 0)); err != nil {
					t.Fatal(err)
				}
			case "fs-type":
				fs.Type = 0x01021994 // tmpfs is NOT immutable, even with RO.
			case "fs-readonly":
				fs.Flags &^= 1
			case "fs-tuple":
				fs.Blocks++
			case "fs-error":
				s.readFilesystem = func(*os.File) (syscall.Statfs_t, error) { return syscall.Statfs_t{}, errors.New("unknown FS") }
			case "closing-fs", "closing-content":
				calls := 0
				s.readFilesystem = func(*os.File) (syscall.Statfs_t, error) {
					calls++
					if kind == "closing-fs" && calls == 2 {
						altered := *fs
						altered.Flags &^= 1
						return altered, nil
					}
					if kind == "closing-content" && calls == 1 {
						if _, err := image.file.WriteAt([]byte("changed"), 0); err != nil {
							t.Fatal(err)
						}
					}
					return *fs, nil
				}
			case "closed":
				_ = image.file.Close()
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if s.unchanged(ctx) {
				t.Fatal("changed image/owner/FS accepted", kind)
			}
		})
	}
}

func TestMutableAndUnknownImageContentStillRequiresFullHash(t *testing.T) {
	for _, kind := range []string{"writable-squash-model", "readonly-tmpfs", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, image, fs := immutableImageModel(t, false)
			if kind == "writable-squash-model" {
				fs.Flags &^= 1
			} else if kind == "readonly-tmpfs" {
				fs.Type = 0x01021994
			} else {
				s.readFilesystem = func(*os.File) (syscall.Statfs_t, error) { return syscall.Statfs_t{}, ErrUnknown }
			}
			if kind != "unknown" && immutableImageFilesystem(*fs) {
				t.Fatal("nonimmutable filesystem classified immutable")
			}
			if !s.unchanged(t.Context()) {
				t.Fatal("unchanged mutable fallback refused")
			}
			if _, err := image.file.WriteAt([]byte("changed"), 0); err != nil {
				t.Fatal(err)
			}
			// Model identical metadata for a changed byte image to distinguish a
			// real content check from a metadata/TTL cache. Keep the original hash.
			current, err := image.file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			image.info = current
			image.nodes[0].info = current
			if s.unchanged(t.Context()) {
				t.Fatal("mutable fallback accepted different content")
			}
		})
	}
}
