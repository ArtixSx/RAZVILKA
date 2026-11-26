package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type externalBootstrapMutationContext struct {
	context.Context
	mutate func()
}

func (c *externalBootstrapMutationContext) Err() error {
	if c.mutate != nil {
		fn := c.mutate
		c.mutate = nil
		fn()
	}
	return c.Context.Err()
}

func TestExternalBootstrapArchiveCopyPinsSourceAndPreservesFailure(t *testing.T) {
	for _, kind := range []string{"verified", "wrong-sha", "source-mutated", "existing-copy", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			work, jobPath := t.TempDir(), t.TempDir()
			source := filepath.Join(work, "package.tar.gz")
			payload := bytes.Repeat([]byte("opaque verified external package\n"), 140000)
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			job, err := ownedfs.Open(jobPath)
			if err != nil {
				t.Fatal(err)
			}
			defer job.Close()
			expected := digestBytes(payload)
			ctx := context.Context(context.Background())
			switch kind {
			case "wrong-sha":
				expected = strings.Repeat("f", 64)
			case "source-mutated":
				ctx = &externalBootstrapMutationContext{Context: ctx, mutate: func() {
					if err := os.WriteFile(source, bytes.Repeat([]byte("changed"), len(payload)/7), 0600); err != nil {
						t.Fatal(err)
					}
				}}
			case "existing-copy":
				if err := os.WriteFile(filepath.Join(jobPath, "release.tar.gz"), []byte("preserve prior partial evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(work, "linked.tar.gz")
				if err := os.Symlink(source, link); err != nil {
					t.Skip("symlink unavailable")
				}
				source = link
			}
			n, err := copyExternalBootstrapArchive(ctx, source, expected, job)
			if kind == "verified" {
				if err != nil || n != int64(len(payload)) {
					t.Fatal("streamed package copy failed", n, err)
				}
				copied, err := os.ReadFile(filepath.Join(jobPath, "release.tar.gz"))
				if err != nil || !bytes.Equal(copied, payload) {
					t.Fatal("verified private copy differs", err)
				}
				return
			}
			if err == nil {
				t.Fatal("unverified input gained a package copy")
			}
			if kind == "existing-copy" {
				copied, err := os.ReadFile(filepath.Join(jobPath, "release.tar.gz"))
				if err != nil || string(copied) != "preserve prior partial evidence" {
					t.Fatal("prior unknown copy overwritten", err)
				}
			}
			if kind == "wrong-sha" || kind == "source-mutated" {
				if _, err := os.Stat(filepath.Join(jobPath, "release.tar.gz")); err != nil {
					t.Fatal("failed copy was pruned", err)
				}
			}
		})
	}
}

func TestExternalBootstrapRefusesUnknownNamespaceAndDoesNotReplaceClaim(t *testing.T) {
	path := t.TempDir()
	owned := func(string) error { return nil }
	ctx := context.Background()
	if err := emptyExternalBootstrapNamespace(ctx, path, owned); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(path, "unknown-old-helper")
	if err := os.WriteFile(unknown, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(emptyExternalBootstrapNamespace(ctx, path, owned), ErrExternalBootstrap) {
		t.Fatal("unknown retained owner was adopted")
	}
	if data, err := os.ReadFile(unknown); err != nil || string(data) != "preserve" {
		t.Fatal("unknown evidence changed")
	}
	root, err := ownedfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first := updateRecord{Owner: updaterOwner, Job: Job{ID: strings.Repeat("a", 32), State: "preparing"}}
	if err := writeInitialExternalBootstrap(root, first); err != nil {
		t.Fatal(err)
	}
	before, _ := root.ReadLimited("current.json", 64<<10)
	second := first
	second.Job.ID = strings.Repeat("b", 32)
	if err := writeInitialExternalBootstrap(root, second); err == nil {
		t.Fatal("second entry overwrote the original owner")
	}
	after, _ := root.ReadLimited("current.json", 64<<10)
	if !bytes.Equal(before, after) {
		t.Fatal("original owner claim changed")
	}
}

func TestExternalBootstrapInvalidOwnerAndPlatformRefuseBeforeAnyPublication(t *testing.T) {
	a, _, review := bootstrapOwnerFixture(t)
	called := false
	owner := func(context.Context, string) error { called = true; return nil }
	_, err := a.BootstrapExternalOld193(context.Background(), review.ID, review.Bootstrap.ArchivePath, review.Bootstrap.ArchiveSHA256, owner, nil)
	if !errors.Is(err, ErrExternalBootstrap) || called {
		t.Fatal("ineligible public producer reached owner/effects", err)
	}
}

func TestExternalBootstrapRetainedLegacyControllerIsNeverRetiredByCopy(t *testing.T) {
	ctx, path := context.Background(), t.TempDir()
	owned := func(string) error { return nil }
	prior := filepath.Join(path, "prior-raw-install")
	if err := os.Mkdir(prior, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prior, "config.json"), []byte("opaque fresh install artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := externalBootstrapLegacyControllersAbsent(ctx, path, owned); err != nil {
		t.Fatal("raw install artifact without prior executable was adopted as controller", err)
	}
	binary := filepath.Join(prior, "razvilka.bin")
	if err := os.WriteFile(binary, []byte("unknown prior controller"), 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(externalBootstrapLegacyControllersAbsent(ctx, path, owned), ErrExternalBootstrap) {
		t.Fatal("unknown retained executable obtained bootstrap eligibility")
	}
	if data, err := os.ReadFile(binary); err != nil || string(data) != "unknown prior controller" {
		t.Fatal("unknown prior controller was pruned")
	}
}
