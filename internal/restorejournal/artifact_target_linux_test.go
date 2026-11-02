//go:build linux

package restorejournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func artifactFixtureImage(t *testing.T, root string, data []byte) Image {
	t.Helper()
	hash := sha256.Sum256(data)
	sha := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(root, sha+".bin"), data, 0555); err != nil {
		t.Fatal(err)
	}
	image, err := ArtifactImage(sha, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return image
}
func TestArtifactTargetStreamsLargeBinaryAndRollsBackThroughSameJournal(t *testing.T) {
	base := t.TempDir()
	artifacts := filepath.Join(base, "artifacts")
	journal := filepath.Join(base, "journal")
	for _, path := range []string{artifacts, journal} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	oldData := bytes.Repeat([]byte("old-binary"), 500000)
	newData := bytes.Repeat([]byte("new-binary"), 600000)
	old := artifactFixtureImage(t, artifacts, oldData)
	next := artifactFixtureImage(t, artifacts, newData)
	path := filepath.Join(base, "mihomo")
	target, err := OpenArtifactExecutableTarget(path, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ctx := context.Background()
	if err := target.CompareAndSwap(ctx, Image{}, old); err != nil {
		t.Fatal(err)
	}
	fault := &artifactFaultTarget{ArtifactFileTarget: target, fail: true}
	j, err := Open(journal, target.Binding(), map[string]Target{"binary": fault})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Execute(ctx, map[string]Image{"binary": next}); err == nil {
		t.Fatal("post-rename failure hidden")
	}
	if _, err := j.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, oldData) {
		t.Fatal("large before-image not recovered", err)
	}
	if image, err := target.Read(ctx); err != nil || !equal(image, old) || len(image.Data) > 200 {
		t.Fatal("journal embedded binary or lost exact reference", err)
	}
	if _, err := j.Execute(ctx, map[string]Image{"binary": next}); err != nil {
		t.Fatal(err)
	}
	actual, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, newData) {
		t.Fatal("complete large replacement missing", err)
	}
}

type artifactFaultTarget struct {
	*ArtifactFileTarget
	fail bool
}

func (t *artifactFaultTarget) CompareAndSwap(ctx context.Context, before, after Image) error {
	if err := t.ArtifactFileTarget.CompareAndSwap(ctx, before, after); err != nil {
		return err
	}
	if t.fail {
		t.fail = false
		return errors.New("actual rename completed; journal commit failed")
	}
	return nil
}

func TestArtifactTargetRefusesForeignArtifactAndRootReplacement(t *testing.T) {
	for _, change := range []string{"artifact-content", "artifact-hardlink", "artifact-root", "target-root", "cancel", "malformed-reference"} {
		t.Run(change, func(t *testing.T) {
			base := t.TempDir()
			artifacts := filepath.Join(base, "artifacts")
			bin := filepath.Join(base, "bin")
			for _, path := range []string{artifacts, bin} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			data := []byte("original reviewed artifact")
			image := artifactFixtureImage(t, artifacts, data)
			ref, _ := artifactImageReference(image)
			source := filepath.Join(artifacts, ref.SHA256+".bin")
			target, err := OpenArtifactExecutableTarget(filepath.Join(bin, "mihomo"), artifacts)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "artifact-content":
				if err := os.Chmod(source, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, []byte("changed"), 0555); err != nil {
					t.Fatal(err)
				}
			case "artifact-hardlink":
				if err := os.Link(source, source+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "artifact-root":
				if err := os.Rename(artifacts, artifacts+"-held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(artifacts, 0700); err != nil {
					t.Fatal(err)
				}
				artifactFixtureImage(t, artifacts, data)
			case "target-root":
				if err := os.Rename(bin, bin+"-held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(bin, 0700); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "malformed-reference":
				image.Data = append([]byte(`{"path":"/foreign",`), image.Data[1:]...)
			}
			if err := target.CompareAndSwap(ctx, Image{}, image); err == nil {
				t.Fatal("unreviewed artifact published")
			}
			if _, err := os.Lstat(filepath.Join(bin, "mihomo")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created executable", err)
			}
		})
	}
}
