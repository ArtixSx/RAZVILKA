//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Actual protected filesystem metadata; no executable or tool lease is issued.
func TestVersionExtensionPathKeepsFreshSymlinkAndMembershipProof(t *testing.T) {
	for _, change := range []string{"none", "symlink", "membership", "directory-inode"} {
		t.Run(change, func(t *testing.T) {
			dir, r := rootReviewFixture(t)
			target, other, alias := filepath.Join(dir, "original"), filepath.Join(dir, "other"), filepath.Join(dir, "alias")
			for _, path := range []string{target, other} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("original", alias); err != nil {
				t.Fatal(err)
			}
			r.profile.extension = alias
			canonical, err := r.resolve(alias)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.retainExtensionPath(canonical); err != nil {
				t.Fatal(err)
			}
			actual, err := r.resolveExisting(alias)
			derived, deriveErr := r.versionExtensionPath()
			if err != nil || deriveErr != nil || actual != derived || derived != target {
				t.Fatal("original derivation differs", err, deriveErr)
			}
			if err := r.versionMetadataCurrent(context.Background()); err != nil {
				t.Fatal("original metadata", err)
			}
			switch change {
			case "symlink":
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other", alias); err != nil {
					t.Fatal(err)
				}
			case "membership":
				if err := os.WriteFile(filepath.Join(target, "new.so"), []byte("not an executable grant"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-inode":
				if err := os.Rename(target, target+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			}
			err = r.versionMetadataCurrent(context.Background())
			if (err == nil) != (change == "none") {
				t.Fatal("fresh graph proof changed", change, err)
			}
		})
	}
}

func TestVersionExtensionPathRefusesCopiedForeignAndChangedSources(t *testing.T) {
	dir, r := rootReviewFixture(t)
	r.profile.extension = dir
	canonical, err := r.resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.retainExtensionPath(canonical); err != nil {
		t.Fatal(err)
	}
	e := r.extensionPath
	foreign := &heldReview{profile: r.profile, nodes: r.nodes, extensionPath: e}
	if path, err := foreign.versionExtensionPath(); err == nil || path != "" {
		t.Fatal("foreign review borrowed derivation")
	}
	r.extensionPath = &reviewedExtensionPath{self: e, review: r, profile: e.profile, alias: e.alias, canonical: e.canonical, target: e.target}
	if path, err := r.versionExtensionPath(); err == nil || path != "" {
		t.Fatal("copied derivation accepted")
	}
	r.extensionPath = e
	r.profile.extension = dir + "/changed"
	if path, err := r.versionExtensionPath(); err == nil || path != "" {
		t.Fatal("changed alias accepted")
	}
	r.profile.extension = dir
	r.profile.id = "changed"
	if path, err := r.versionExtensionPath(); err == nil || path != "" {
		t.Fatal("changed profile accepted")
	}
}
