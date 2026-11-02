package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestNFQWSProbeProcessRootRetainsOriginalMarkerAndRefusesSafeReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux private writer marker and root inode semantics")
	}
	for _, kind := range []string{"marker", "root"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "root" && runtime.GOOS != "linux" {
				t.Skip("Linux descriptor-root rename semantics")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := privateScopedXrayFixtureDir(t)
			targetPath := filepath.Join(path, nfqws2LeaseFile)
			target, err := restorejournal.OpenFileTarget(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			owner, err := newNFQWSProbeProcessRoot(ctx, path, target)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.close()
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			if err := owner.current(ctx); err != nil {
				t.Fatal("handover released original marker witness", err)
			}
			if kind == "marker" {
				markerPath := filepath.Join(path, owner.markerName)
				temporary := markerPath + ".new"
				if err := os.WriteFile(temporary, owner.markerBytes, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(temporary, markerPath); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path, path+"-original"); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(path + "-original")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, owner.markerName), owner.markerBytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			foreign, err := restorejournal.OpenExistingFileTarget(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			if owner.matchesTarget(ctx, foreign) == nil {
				t.Fatal("equal safe replacement adopted original process-root authority")
			}
			if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
				t.Fatal("refused replacement initialized receipt", err)
			}
		})
	}
}
