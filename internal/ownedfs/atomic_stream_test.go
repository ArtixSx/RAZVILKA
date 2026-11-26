package ownedfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicStreamPublishesVerifiedArtifactBeyondPrivateImageLimit(t *testing.T) {
	root, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data := bytes.Repeat([]byte("native-artifact"), 400000)
	count := 0
	attempted, err := root.WriteAtomicStreamWithRenameAdmission(context.Background(), "binary", bytes.NewReader(data), int64(len(data)), sha256.Sum256(data), 0755, func(rename func() error) error { count++; return rename() }, nil)
	if err != nil || !attempted || count != 1 {
		t.Fatal(attempted, count, err)
	}
	actual, err := root.ReadLimited("binary", MaxAtomicArtifactBytes)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("artifact bytes changed", err)
	}
}

func TestAtomicStreamRefusalPreservesExistingTarget(t *testing.T) {
	for _, kind := range []string{"short", "long", "digest", "cancel", "prepared", "skip", "repeat", "source-error"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			root, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := os.WriteFile(filepath.Join(path, "binary"), []byte("old"), 0755); err != nil {
				t.Fatal(err)
			}
			data := []byte("verified new artifact")
			size := int64(len(data))
			digest := sha256.Sum256(data)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prepare := func() error { return nil }
			admit := func(rename func() error) error { return rename() }
			var reader interface{ Read([]byte) (int, error) } = bytes.NewReader(data)
			switch kind {
			case "short":
				size++
			case "long":
				size--
			case "digest":
				digest[0] ^= 1
			case "cancel":
				prepare = func() error { cancel(); return nil }
			case "prepared":
				prepare = func() error { return errors.New("source inode changed") }
			case "skip":
				admit = func(func() error) error { return nil }
			case "repeat":
				admit = func(rename func() error) error { _ = rename(); _ = rename(); return nil }
			case "source-error":
				reader = atomicBrokenStream{}
			}
			attempted, err := root.WriteAtomicStreamWithRenameAdmission(ctx, "binary", reader, size, digest, 0755, admit, prepare)
			if err == nil {
				t.Fatal("invalid stream/admission accepted")
			}
			actual, readErr := os.ReadFile(filepath.Join(path, "binary"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if kind == "repeat" {
				if !attempted || !bytes.Equal(actual, data) {
					t.Fatal("repeated call hid attempted rename")
				}
			} else if attempted || string(actual) != "old" {
				t.Fatal("pre-publication failure changed target")
			}
			entries, _ := os.ReadDir(path)
			if len(entries) != 1 {
				t.Fatal("stage cleanup leaked", entries)
			}
		})
	}
}

type atomicBrokenStream struct{}

func (atomicBrokenStream) Read([]byte) (int, error) { return 0, errors.New("source read failed") }
