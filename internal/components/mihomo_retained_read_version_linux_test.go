//go:build linux

package components

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMihomoCachePublicationCutReaderAndRetry(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_CACHE_CUT") == "1" {
		m := New()
		m.StateDir = os.Getenv("RAZVILKA_MIHOMO_TEST_STATE")
		m.BinDir = os.Getenv("RAZVILKA_MIHOMO_TEST_BIN")
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		_, _ = z.Write([]byte("publication cut artifact"))
		_ = z.Close()
		_, _ = m.stageMihomoArtifact(context.Background(), b.Bytes(), digest(b.Bytes()), func(context.Context, func() error) error { os.Exit(109); return nil })
		t.Fatal("publication cut missing")
	}
	m, info := mihomoReleaseFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMihomoCachePublicationCutReaderAndRetry$")
	cmd.Env = append(os.Environ(), "RAZVILKA_MIHOMO_CACHE_CUT=1", "RAZVILKA_MIHOMO_TEST_STATE="+m.StateDir, "RAZVILKA_MIHOMO_TEST_BIN="+m.BinDir)
	out, err := cmd.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 109 {
		t.Fatalf("missing actual cut: %v %s", err, out)
	}
	_, _, cache, _, _ := m.mihomoReleaseLayout()
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	stages := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".transaction-") {
			stages++
		}
	}
	if stages != 1 {
		t.Fatal("actual atomic stage missing", stages)
	}
	if v, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); err != nil || v != MihomoReleaseReadVersion {
		t.Fatal("prejournal crash falsely became unreadable", v, err)
	}
	image := mihomoFixtureStage(t, m, []byte("publication cut artifact"))
	if result, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
		t.Fatal("known inert stage prevented a new verified install", result, err)
	}
	mihomoAssertInstalled(t, m, []byte("publication cut artifact"))
}

func TestMihomoReaderRequiredBeforeFirstJournal(t *testing.T) {
	m, info := mihomoReleaseFixture(t)
	ctx := context.Background()
	if v, err := RequiredRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || v != ComponentUpdateSchema {
		t.Fatal(v, err)
	}
	image := mihomoFixtureStage(t, m, bytes.Repeat([]byte("closed-artifact"), 400000))
	v, seal, err := InspectRetainedManagedUpdateReadVersion(ctx, m.StateDir)
	if err != nil || v != MihomoReleaseReadVersion || len(seal) != 64 {
		t.Fatal("cache alone must require new reader", v, seal, err)
	}
	if _, err := m.installMihomoImage(ctx, info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil {
		t.Fatal(err)
	}
	v, next, err := InspectRetainedManagedUpdateReadVersion(ctx, m.StateDir)
	if err != nil || v != MihomoReleaseReadVersion || next == seal {
		t.Fatal("journal/receipts missing from format observation", v, err)
	}
	if v, again, err := InspectRetainedManagedUpdateReadVersion(ctx, m.StateDir); err != nil || v != MihomoReleaseReadVersion || again != next {
		t.Fatal("read-only scan changed metadata", v, again, err)
	}
}

func TestMihomoReaderRefusesForeignCache(t *testing.T) {
	for _, change := range []string{"name", "mode", "hardlink", "symlink", "directory", "stage"} {
		t.Run(change, func(t *testing.T) {
			m, _ := mihomoReleaseFixture(t)
			image := mihomoFixtureStage(t, m, []byte("model-image"))
			_, _, root, _, _ := m.mihomoReleaseLayout()
			ref, _ := mihomoArtifactReferenceOf(image)
			path := filepath.Join(root, ref.SHA256+".bin")
			var err error
			switch change {
			case "name":
				err = os.WriteFile(filepath.Join(root, "arbitrary"), []byte("x"), 0600)
			case "mode":
				err = os.Chmod(path, 0755)
			case "hardlink":
				err = os.Link(path, filepath.Join(t.TempDir(), "alias"))
			case "symlink":
				err = os.Symlink(path, filepath.Join(root, strings.Repeat("a", 64)+".bin"))
			case "directory":
				err = os.Mkdir(filepath.Join(root, "extra"), 0700)
			case "stage":
				err = os.WriteFile(filepath.Join(root, ".mihomo-stage-"+strings.Repeat("A", 26)), []byte("inert partial stage"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			v, err := RequiredRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
			if change == "stage" {
				if err != nil || v != 6 {
					t.Fatal("inert stage lost reader fence", v, err)
				}
			} else if err == nil {
				t.Fatal("foreign cache accepted", v)
			}
		})
	}
}
