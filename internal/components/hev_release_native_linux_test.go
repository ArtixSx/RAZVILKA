//go:build linux

package components

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// Uses the exact pinned official executable through the production downloader,
// digest verifier, --version observation and durable install transaction. The
// HTTP transport only supplies the already downloaded pinned fixture locally;
// this test needs no GitHub credentials and starts no HEV TUN or service.
func TestHEVReleasePinnedNativeInstall(t *testing.T) {
	path := os.Getenv("RAZVILKA_HEV_NATIVE")
	if path == "" {
		t.Skip("set absolute path to pinned official HEV 2.17.1 amd64 fixture")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("HEV fixture must be absolute")
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, spec, info := hevReleaseFixture(t)
	requests := 0
	m.Client = &http.Client{Transport: hevReleaseTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != info.Asset.URL {
			t.Fatal("unreviewed release URL", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(binary)), Header: make(http.Header)}, nil
	})}
	for i := 0; i < 2; i++ {
		result, err := m.ApplyHEVGuarded(context.Background(), func(_ context.Context, mutate func() error) error { return mutate() }, func(_ context.Context, rename func() error) error { return rename() })
		if err != nil || !result.OK {
			t.Fatalf("install round %d: %+v %v", i, result, err)
		}
		hevAssertPair(t, m, binary)
		if err := verifyHEVRelease(context.Background(), filepath.Join(m.BinDir, spec.Binary)); err != nil {
			t.Fatal(err)
		}
		if err := m.hevReleaseIdle(); err != nil {
			t.Fatal(err)
		}
		if observed, err := m.CheckInstalledHEV(context.Background()); err != nil || observed != filepath.Join(m.BinDir, spec.Binary) {
			t.Fatal("original pinned installation not observed", observed, err)
		}
	}
	if requests != 2 {
		t.Fatal(requests)
	}
	fresh := New()
	fresh.StateDir = m.StateDir
	fresh.BinDir = m.BinDir
	if _, err := fresh.RecoverHEVRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Installed remains registered bytes, not native route/probe acceptance.
	if _, err := os.Stat(filepath.Join(m.StateDir, "receipts", spec.ID+".json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.BinDir, spec.Binary), []byte("foreign same-version text is insufficient"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CheckInstalledHEV(context.Background()); err == nil {
		t.Fatal("foreign executable revived from retained receipt")
	}
}
