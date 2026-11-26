//go:build linux && razvilka_native_fixture

package components

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
)

type initialUSQUEFixtureTransport func(*http.Request) (*http.Response, error)

func (f initialUSQUEFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestInstallInitialUSQUEPinnedNative(t *testing.T) {
	archivePath := os.Getenv("RAZVILKA_USQUE_INSTALL_NATIVE_ARCHIVE")
	if archivePath == "" {
		t.Skip("isolated USQUE install fixture not enabled")
	}
	// Only an otherwise empty tmpfs /opt with the suite's marker is allowed.
	entries, dirErr := os.ReadDir("/opt")
	mounts, mountErr := os.ReadFile("/proc/self/mountinfo")
	private := false
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 6 && fields[4] == "/opt" && strings.Contains(line, " - tmpfs ") {
			private = true
		}
	}
	if dirErr != nil || mountErr != nil || len(entries) != 1 || entries[0].Name() != ".razvilka-usque-lab" || !private {
		t.Fatal("fixture requires an isolated tmpfs /opt")
	}
	if err := os.MkdirAll(installpath.State, 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := reviewedUSQUEBinary(runtime.GOARCH, archive)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(archive)
	corrupt[len(corrupt)-1] ^= 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m := New()
	response := corrupt
	requests := 0
	m.Client = &http.Client{Transport: initialUSQUEFixtureTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		want := "https://github.com/Diniboy1123/usque/releases/download/v4.2.1/usque_4.2.1_linux_" + runtime.GOARCH + ".zip"
		if req.Method != http.MethodGet || req.URL.String() != want {
			t.Fatalf("unexpected release request: %s %s", req.Method, req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(response)), Header: http.Header{}}, nil
	})}
	permit := context.Context.Err
	if result, err := m.InstallInitialUSQUE(ctx, permit); result.OK || !errors.Is(err, ErrNoMutation) {
		t.Fatalf("corrupt archive: %+v %v", result, err)
	}
	if _, err := os.Lstat(installpath.ManagedUSQUE); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt archive published a file: %v", err)
	}
	response = archive
	if result, err := m.InstallInitialUSQUE(ctx, permit); !result.OK || err != nil {
		t.Fatalf("pinned archive: %+v %v", result, err)
	}
	if filepath.Base(installpath.ManagedUSQUE) != "usque" {
		t.Fatal("installed name must match the process identity expected by routeidentity")
	}
	if err := m.CheckInitialUSQUEPublication(ctx); err != nil {
		t.Fatalf("installed executable publication: %v", err)
	}
	if actual, err := os.ReadFile(installpath.ManagedUSQUE); err != nil || !bytes.Equal(actual, verified) {
		t.Fatalf("installed executable failed exact readback: %v", err)
	}
	if version, err := exec.CommandContext(ctx, installpath.ManagedUSQUE, "version").CombinedOutput(); err != nil || !bytes.Contains(version, []byte("v4.2.1")) {
		t.Fatalf("installed executable version: %q %v", version, err)
	}
	if _, err := m.InstallInitialUSQUE(ctx, permit); !errors.Is(err, ErrComponentAlreadyInstalled) || requests != 2 {
		t.Fatalf("repeated install requested archive or replaced existing core: %v requests=%d", err, requests)
	}
	for _, path := range []string{"/opt/bin/usque", "/opt/etc/init.d/S51usque", "/opt/etc/usque"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("binary-only install created vendor state: %s %v", path, err)
		}
	}
	items, err := os.ReadDir(filepath.Dir(installpath.ManagedUSQUE))
	if err != nil || len(items) != 2 {
		t.Fatalf("component root contents: %v %v", items, err)
	}
}
